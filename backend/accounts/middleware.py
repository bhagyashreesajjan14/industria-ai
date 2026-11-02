from django.shortcuts import redirect
from django.http import JsonResponse
from django.urls import reverse
from django.contrib.auth import logout
from .models import SecurityAuditLog


class MFAGateMiddleware:
    """
    Production Security Middleware:
    Enforces that every authenticated session must have completed TOTP MFA verification
    before accessing any dashboard page or protected backend REST API.
    Prevents bypassing MFA via direct URL manipulation or API requests.
    """

    EXEMPT_PREFIXES = [
        '/mfa/',
        '/api/auth/',
        '/login/',
        '/static/',
        '/media/',
        '/admin/login/',
        '/favicon.ico',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Always permit public/auth paths
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        user = getattr(request, 'user', None)

        # If user is authenticated, enforce MFA verification
        if user and user.is_authenticated:
            # Check account lockout
            if getattr(user, 'is_locked', False):
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.ACCOUNT_LOCKED,
                    user=user,
                    portal='MIDDLEWARE',
                    details={"action": "session_terminated_due_to_lockout"}
                )
                logout(request)
                if path.startswith('/api/'):
                    return JsonResponse({
                        "error": "ACCOUNT_LOCKED",
                        "detail": "Account is temporarily locked due to security policy."
                    }, status=403)
                return redirect('/login/?error=locked')

            is_mfa_verified = request.session.get('is_mfa_verified', False)

            if not is_mfa_verified:
                # Log blocked bypass attempt
                SecurityAuditLog.log(
                    request=request,
                    event_type=SecurityAuditLog.EventType.MFA_BYPASS_ATTEMPT,
                    user=user,
                    portal='MIDDLEWARE',
                    details={"attempted_path": path}
                )

                # For API endpoints, return strict HTTP 403 Forbidden
                if path.startswith('/api/'):
                    return JsonResponse({
                        "error": "MFA_REQUIRED",
                        "detail": "Multi-Factor Authentication (TOTP) verification is required before accessing this endpoint."
                    }, status=403)

                # For browser pages, check if user has enrolled or needs setup
                has_mfa = hasattr(user, 'mfa') and user.mfa.is_enabled
                if has_mfa:
                    return redirect(f"/mfa/verify/?next={path}")
                else:
                    return redirect(f"/mfa/setup/?next={path}")

        return self.get_response(request)
