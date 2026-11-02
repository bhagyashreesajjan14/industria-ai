from django.shortcuts import redirect
from django.http import JsonResponse
from django.contrib.auth import logout
from .models import SecurityAuditLog


class SecurityEnforcementMiddleware:
    """
    Security Middleware:
    Enforces account lockout checks across authenticated requests.
    If an account is flagged as locked due to security policy/brute-force protection,
    it flushes the session, logs the event, and terminates access.
    """

    EXEMPT_PREFIXES = [
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

        # If user is authenticated, enforce account security policies
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

        return self.get_response(request)


# Alias for compatibility with existing settings references
MFAGateMiddleware = SecurityEnforcementMiddleware
