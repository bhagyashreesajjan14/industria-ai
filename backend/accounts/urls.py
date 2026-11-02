from django.urls import path
from .views import (
    LoginView,
    LogoutView,
    CurrentUserView,
    MFAVerifyView,
    MFASetupView,
    SecurityAuditLogView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='auth_login'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('me/', CurrentUserView.as_view(), name='auth_me'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='auth_mfa_verify'),
    path('mfa/setup/', MFASetupView.as_view(), name='auth_mfa_setup'),
    path('audit-logs/', SecurityAuditLogView.as_view(), name='auth_audit_logs'),
]
