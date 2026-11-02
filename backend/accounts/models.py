import hashlib
import secrets
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
import pyotp


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Administrator'
        ENGINEER = 'ENGINEER', 'Engineer'
        SUPERVISOR = 'SUPERVISOR', 'Supervisor'

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.ENGINEER,
        help_text="Role determining application permissions"
    )
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False

    def record_failed_login(self, max_attempts=5, lockout_minutes=15):
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'locked_until'])

    def reset_failed_logins(self):
        if self.failed_login_attempts > 0 or self.locked_until is not None:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=['failed_login_attempts', 'locked_until'])

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN or self.is_superuser

    @property
    def is_engineer_role(self):
        return self.role == self.Role.ENGINEER

    @property
    def is_supervisor_role(self):
        return self.role == self.Role.SUPERVISOR

    def __str__(self):
        return f"{self.username} ({self.role})"


class UserMFA(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa')
    is_enabled = models.BooleanField(default=False)
    secret_key = models.CharField(max_length=64, blank=True)
    recovery_codes = models.JSONField(default=list, blank=True)
    enrolled_at = models.DateTimeField(null=True, blank=True)

    def generate_secret(self):
        self.secret_key = pyotp.random_base32()
        return self.secret_key

    def get_totp_uri(self):
        if not self.secret_key:
            self.generate_secret()
        return pyotp.totp.TOTP(self.secret_key).provisioning_uri(
            name=self.user.username,
            issuer_name="INDUSTRIA AI"
        )

    def verify_token(self, token: str) -> bool:
        if not self.secret_key:
            return False
        totp = pyotp.TOTP(self.secret_key)
        return bool(totp.verify(str(token).strip(), valid_window=1))

    def generate_recovery_codes(self, count=8):
        plaintext_codes = []
        hashed_records = []
        for _ in range(count):
            raw_code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
            code_hash = hashlib.sha256(raw_code.encode('utf-8')).hexdigest()
            plaintext_codes.append(raw_code)
            hashed_records.append({
                "hash": code_hash,
                "used": False,
                "created_at": timezone.now().isoformat()
            })
        self.recovery_codes = hashed_records
        return plaintext_codes

    def verify_recovery_code(self, raw_code: str) -> bool:
        if not raw_code:
            return False
        clean_code = raw_code.strip().upper()
        code_hash = hashlib.sha256(clean_code.encode('utf-8')).hexdigest()
        for item in self.recovery_codes:
            if item.get("hash") == code_hash and not item.get("used"):
                item["used"] = True
                item["used_at"] = timezone.now().isoformat()
                self.save(update_fields=['recovery_codes'])
                return True
        return False

    def __str__(self):
        return f"MFA for {self.user.username} (Enabled: {self.is_enabled})"


class SecurityAuditLog(models.Model):
    class EventType(models.TextChoices):
        LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login Successful'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
        PORTAL_ROLE_MISMATCH = 'PORTAL_ROLE_MISMATCH', 'Portal Role Mismatch'
        ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account Locked'
        ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED', 'Account Unlocked'
        LOGOUT = 'LOGOUT', 'User Logged Out'
        MFA_SETUP_INITIATED = 'MFA_SETUP_INITIATED', 'MFA Setup Initiated'
        MFA_ENROLLED = 'MFA_ENROLLED', 'MFA Enrolled Successfully'
        MFA_VERIFIED = 'MFA_VERIFIED', 'MFA Verification Successful'
        MFA_FAILED = 'MFA_FAILED', 'MFA Verification Failed'
        MFA_RECOVERY_USED = 'MFA_RECOVERY_USED', 'MFA Recovery Code Used'
        MFA_BYPASS_ATTEMPT = 'MFA_BYPASS_ATTEMPT', 'MFA Bypass Attempt Blocked'
        ROLE_CHANGED = 'ROLE_CHANGED', 'User Role Changed'
        PASSWORD_CHANGED = 'PASSWORD_CHANGED', 'Password Changed'

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=50, choices=EventType.choices, db_index=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='security_logs')
    username_attempted = models.CharField(max_length=150, blank=True)
    portal = models.CharField(max_length=50, blank=True)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Security Audit Log'
        verbose_name_plural = 'Security Audit Logs'

    @classmethod
    def log(cls, request, event_type, user=None, username_attempted='', portal='', details=None):
        ip = None
        user_agent = ''
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:250]

        safe_details = details or {}
        # Strictly sanitize: Never store passwords, MFA tokens, secret keys, or recovery codes in logs
        for sensitive_key in ['password', 'secret', 'secret_key', 'token', 'totp', 'code', 'recovery_code']:
            safe_details.pop(sensitive_key, None)

        return cls.objects.create(
            event_type=event_type,
            user=user,
            username_attempted=username_attempted or (user.username if user else ''),
            portal=portal,
            ip_address=ip,
            user_agent=user_agent,
            details=safe_details
        )
