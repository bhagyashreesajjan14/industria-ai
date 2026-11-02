import io
import base64
import logging
import qrcode
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import User, UserMFA, SecurityAuditLog
from .serializers import UserSerializer

logger = logging.getLogger(__name__)


def get_dashboard_url_for_user(user):
    if user.role == User.Role.ADMIN or user.is_superuser:
        return '/admin-dashboard/'
    elif user.role == User.Role.SUPERVISOR:
        return '/supervisor/'
    return '/engineer/'


class LoginView(APIView):
    """
    Central, secure authentication endpoint supporting distinct portals:
    - Admin (portal='ADMIN')
    - Engineer (portal='ENGINEER')
    - Supervisor (portal='SUPERVISOR')

    Enforces:
    - Rate limiting / account lockout after repeated failed attempts.
    - Protection against username enumeration (uniform error message).
    - Strict server-side role verification for each portal.
    - MFA challenge requirement before granting full session access.
    - Comprehensive security audit logging.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username', '').strip()
        password = request.data.get('password', '')
        portal = request.data.get('portal', '').strip().upper()

        if not username or not password:
            return Response({
                "error": "MISSING_CREDENTIALS",
                "detail": "Username and password are required."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists to evaluate lockout
        target_user = User.objects.filter(username__iexact=username).first()

        if target_user and target_user.is_locked:
            SecurityAuditLog.log(
                request=request,
                event_type=SecurityAuditLog.EventType.ACCOUNT_LOCKED,
                user=target_user,
                username_attempted=username,
                portal=portal,
                details={"reason": "login_attempt_on_locked_account"}
            )
            return Response({
                "error": "ACCOUNT_LOCKED",
                "detail": "Account is temporarily locked due to repeated failed login attempts. Please contact your administrator."
            }, status=status.HTTP_403_FORBIDDEN)

        # Attempt authentication using Django secure hashing
        user = authenticate(request, username=username, password=password)

        if not user:
            # Record failed login
            if target_user:
                target_user.record_failed_login(max_attempts=5, lockout_minutes=15)
                is_now_locked = target_user.is_locked
            else:
                is_now_locked = False

            SecurityAuditLog.log(
                request=request,
                event_type=SecurityAuditLog.EventType.LOGIN_FAILED,
                user=target_user,
                username_attempted=username,
                portal=portal,
                details={"locked": is_now_locked}
            )

            # Uniform safe error message (protects against username enumeration)
            return Response({
                "error": "INVALID_CREDENTIALS",
                "detail": "Invalid username or password."
            }, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({
                "error": "ACCOUNT_INACTIVE",
                "detail": "This account is inactive. Please contact your administrator."
            }, status=status.HTTP_403_FORBIDDEN)

        # Strict Server-Side Portal Role Verification
        if portal:
            if portal == 'ADMIN' and not (user.role == User.Role.ADMIN or user.is_superuser):
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.PORTAL_ROLE_MISMATCH,
                    user=user,
                    username_attempted=username,
                    portal=portal,
                    details={"user_role": user.role, "required_portal": portal}
                )
                return Response({
                    "error": "PORTAL_ROLE_MISMATCH",
                    "detail": "Access denied: This login portal is restricted to System Administrators only."
                }, status=status.HTTP_403_FORBIDDEN)

            elif portal == 'ENGINEER' and user.role != User.Role.ENGINEER:
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.PORTAL_ROLE_MISMATCH,
                    user=user,
                    username_attempted=username,
                    portal=portal,
                    details={"user_role": user.role, "required_portal": portal}
                )
                return Response({
                    "error": "PORTAL_ROLE_MISMATCH",
                    "detail": "Access denied: This login portal is restricted to Operations & Maintenance Engineers only."
                }, status=status.HTTP_403_FORBIDDEN)

            elif portal == 'SUPERVISOR' and user.role != User.Role.SUPERVISOR:
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.PORTAL_ROLE_MISMATCH,
                    user=user,
                    username_attempted=username,
                    portal=portal,
                    details={"user_role": user.role, "required_portal": portal}
                )
                return Response({
                    "error": "PORTAL_ROLE_MISMATCH",
                    "detail": "Access denied: This login portal is restricted to Compliance Supervisors only."
                }, status=status.HTTP_403_FORBIDDEN)

        # Reset failed attempts upon successful password authentication
        user.reset_failed_logins()

        # Complete Django session authentication
        login(request, user)
        request.session.cycle_key()

        # Security audit log
        SecurityAuditLog.log(
            request=request,
            event_type=SecurityAuditLog.EventType.LOGIN_SUCCESS,
            user=user,
            portal=portal
        )

        redirect_url = get_dashboard_url_for_user(user)

        return Response({
            "message": "Login successful.",
            "redirect_url": redirect_url,
            "user": UserSerializer(user).data
        }, status=status.HTTP_200_OK)


class MFAVerifyView(APIView):
    """
    Verifies TOTP token or single-use recovery code.
    Upon success, completes Django session authentication, cycles the session key,
    and grants dashboard access.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get('token', '').strip()
        recovery_code = request.data.get('recovery_code', '').strip()

        # Retrieve user from pending session or current request
        user_id = request.session.get('mfa_pending_user_id') or (request.user.id if request.user.is_authenticated else None)

        if not user_id:
            return Response({
                "error": "NO_SESSION",
                "detail": "Authentication session expired or not found. Please log in again."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            mfa = user.mfa
        except (User.DoesNotExist, UserMFA.DoesNotExist):
            return Response({
                "error": "USER_NOT_FOUND",
                "detail": "User record not found."
            }, status=status.HTTP_404_NOT_FOUND)

        # 1. Verify via recovery code
        if recovery_code:
            if mfa.verify_recovery_code(recovery_code):
                # Complete authentication
                login(request, user)
                request.session['is_mfa_verified'] = True
                request.session.cycle_key()
                request.session.pop('mfa_pending_user_id', None)

                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.MFA_RECOVERY_USED,
                    user=user,
                    details={"method": "recovery_code"}
                )

                return Response({
                    "message": "Recovery code accepted. Authentication verified.",
                    "redirect_url": get_dashboard_url_for_user(user),
                    "user": UserSerializer(user).data
                }, status=status.HTTP_200_OK)
            else:
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.MFA_FAILED,
                    user=user,
                    details={"method": "recovery_code"}
                )
                return Response({
                    "error": "INVALID_RECOVERY_CODE",
                    "detail": "Invalid or previously used recovery code."
                }, status=status.HTTP_400_BAD_REQUEST)

        # 2. Verify via TOTP code
        if not token:
            return Response({
                "error": "MISSING_TOKEN",
                "detail": "Verification code is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        if mfa.verify_token(token):
            # Complete authentication
            login(request, user)
            request.session['is_mfa_verified'] = True
            request.session.cycle_key()
            request.session.pop('mfa_pending_user_id', None)

            SecurityAuditLog.log(
                request=request,
                event_type=SecurityAuditLog.EventType.MFA_VERIFIED,
                user=user,
                details={"method": "totp"}
            )
            SecurityAuditLog.log(
                request=request,
                event_type=SecurityAuditLog.EventType.LOGIN_SUCCESS,
                user=user,
                portal=request.session.get('mfa_portal', '')
            )

            return Response({
                "message": "MFA verified successfully.",
                "redirect_url": get_dashboard_url_for_user(user),
                "user": UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        else:
            SecurityAuditLog.log(
                request=request,
                event_type=SecurityAuditLog.EventType.MFA_FAILED,
                user=user,
                details={"method": "totp"}
            )
            return Response({
                "error": "INVALID_TOKEN",
                "detail": "Invalid or expired verification code. Please check your authenticator app."
            }, status=status.HTTP_400_BAD_REQUEST)


class MFASetupView(APIView):
    """
    Handles MFA enrollment:
    - GET: Generates TOTP secret, provisioning URI, and Base64 QR code image.
    - POST: Verifies user's first TOTP code, generates 8 single-use recovery codes,
            and permanently activates MFA for the account.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        user_id = request.session.get('mfa_pending_user_id') or (request.user.id if request.user.is_authenticated else None)
        if not user_id:
            return Response({"error": "Session expired. Please log in first."}, status=status.HTTP_401_UNAUTHORIZED)

        user = User.objects.get(id=user_id)
        mfa, _ = UserMFA.objects.get_or_create(user=user)

        if not mfa.secret_key:
            mfa.generate_secret()
            mfa.save(update_fields=['secret_key'])

        totp_uri = mfa.get_totp_uri()

        # Generate QR Code image in-memory as data URI
        qr = qrcode.QRCode(box_size=5, border=2)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#000000", back_color="#ffffff")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        qr_data_uri = f"data:image/png;base64,{qr_base64}"

        SecurityAuditLog.log(
            request=request,
            event_type=SecurityAuditLog.EventType.MFA_SETUP_INITIATED,
            user=user
        )

        return Response({
            "secret_key": mfa.secret_key,
            "totp_uri": totp_uri,
            "qr_data_uri": qr_data_uri,
            "username": user.username
        }, status=status.HTTP_200_OK)

    def post(self, request):
        user_id = request.session.get('mfa_pending_user_id') or (request.user.id if request.user.is_authenticated else None)
        if not user_id:
            return Response({"error": "Session expired. Please log in first."}, status=status.HTTP_401_UNAUTHORIZED)

        user = User.objects.get(id=user_id)
        mfa = user.mfa
        token = request.data.get('token', '').strip()

        if not token:
            return Response({"error": "Verification code is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not mfa.verify_token(token):
            return Response({
                "error": "INVALID_TOKEN",
                "detail": "Verification code does not match. Please verify the code displayed in your authenticator app."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate single-use recovery codes
        plaintext_codes = mfa.generate_recovery_codes(count=8)
        mfa.is_enabled = True
        mfa.enrolled_at = timezone.now()
        mfa.save()

        # Grant full authenticated session
        login(request, user)
        request.session['is_mfa_verified'] = True
        request.session.cycle_key()
        request.session.pop('mfa_pending_user_id', None)

        SecurityAuditLog.log(
            request=request,
            event_type=SecurityAuditLog.EventType.MFA_ENROLLED,
            user=user,
            details={"recovery_codes_count": len(plaintext_codes)}
        )
        SecurityAuditLog.log(
            request=request,
            event_type=SecurityAuditLog.EventType.LOGIN_SUCCESS,
            user=user,
            portal=request.session.get('mfa_portal', '')
        )

        return Response({
            "message": "MFA enrollment complete. Save your recovery codes securely.",
            "recovery_codes": plaintext_codes,
            "redirect_url": get_dashboard_url_for_user(user),
            "user": UserSerializer(user).data
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    Safely invalidates the session, flushes all session data,
    logs the event, and clears authentication cookies.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        SecurityAuditLog.log(
            request=request,
            event_type=SecurityAuditLog.EventType.LOGOUT,
            user=user
        )
        request.session.flush()
        logout(request)
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)


class CurrentUserView(APIView):
    """Returns profile and role information for currently authenticated user."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        data = UserSerializer(user).data
        return Response(data, status=status.HTTP_200_OK)


class SecurityAuditLogView(APIView):
    """
    Returns security audit log history.
    Strictly restricted to Administrators and Supervisors.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not (request.user.role in [User.Role.ADMIN, User.Role.SUPERVISOR] or request.user.is_superuser):
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        event_type = request.query_params.get('event_type')
        username = request.query_params.get('username')
        limit = min(int(request.query_params.get('limit', 50)), 100)

        qs = SecurityAuditLog.objects.all()
        if event_type:
            qs = qs.filter(event_type=event_type)
        if username:
            qs = qs.filter(username_attempted__icontains=username)

        logs = qs[:limit]
        results = [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "event_type": l.event_type,
                "event_display": l.get_event_type_display(),
                "username": l.username_attempted,
                "portal": l.portal,
                "ip_address": l.ip_address,
                "user_agent": l.user_agent,
                "details": l.details
            }
            for l in logs
        ]

        return Response({
            "count": len(results),
            "results": results
        }, status=status.HTTP_200_OK)
