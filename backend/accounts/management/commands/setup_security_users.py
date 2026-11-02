import pyotp
from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import User, UserMFA, SecurityAuditLog


class Command(BaseCommand):
    help = "Setup production security users (Admin, Engineer, Supervisor) with strong passwords and pre-enrolled MFA."

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset MFA and passwords for existing users to defaults',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("=== CONFIGURING INDUSTRIA AI SECURITY ACCOUNTS & MFA ==="))

        users_config = [
            {
                "username": "admin",
                "email": "admin@industria.ai",
                "password": "Admin@Sec2026!",
                "role": User.Role.ADMIN,
                "portal": "/login/admin/",
                "is_staff": True,
                "is_superuser": True,
            },
            {
                "username": "engineer",
                "email": "engineer@industria.ai",
                "password": "Engineer@Sec2026!",
                "role": User.Role.ENGINEER,
                "portal": "/login/engineer/",
                "is_staff": False,
                "is_superuser": False,
            },
            {
                "username": "supervisor",
                "email": "supervisor@industria.ai",
                "password": "Supervisor@Sec2026!",
                "role": User.Role.SUPERVISOR,
                "portal": "/login/supervisor/",
                "is_staff": False,
                "is_superuser": False,
            },
        ]

        summary_table = []

        for item in users_config:
            username = item["username"]
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": item["email"],
                    "role": item["role"],
                    "is_staff": item["is_staff"],
                    "is_superuser": item["is_superuser"],
                }
            )

            # Always set compliant password and reset lockouts
            user.set_password(item["password"])
            user.role = item["role"]
            user.is_staff = item["is_staff"]
            user.is_superuser = item["is_superuser"]
            user.reset_failed_logins()
            user.save()

            # Configure or retrieve UserMFA
            mfa, _ = UserMFA.objects.get_or_create(user=user)

            # If newly created or reset requested or not enabled, setup fresh MFA
            if created or options.get('reset') or not mfa.is_enabled or not mfa.secret_key:
                secret = mfa.generate_secret()
                plaintext_recovery_codes = mfa.generate_recovery_codes(count=8)
                mfa.is_enabled = True
                mfa.enrolled_at = timezone.now()
                mfa.save()
            else:
                secret = mfa.secret_key
                plaintext_recovery_codes = ["(Existing recovery codes active)"]

            totp = pyotp.TOTP(secret)
            current_code = totp.now()

            SecurityAuditLog.log(
                request=None,
                event_type=SecurityAuditLog.EventType.MFA_ENROLLED,
                user=user,
                portal=item["portal"],
                details={"setup_by": "management_command"}
            )

            summary_table.append({
                "username": username,
                "role": item["role"],
                "portal": item["portal"],
                "password": item["password"],
                "secret_key": secret,
                "current_totp": current_code,
                "recovery_codes": plaintext_codes_display if 'plaintext_codes_display' in locals() else plaintext_recovery_codes,
            })

            status_str = "Created" if created else "Updated"
            self.stdout.write(self.style.SUCCESS(f"\n[+] {status_str} User: {username} ({item['role']})"))
            self.stdout.write(f"    Portal URL:       {item['portal']}")
            self.stdout.write(f"    Password:         {item['password']}")
            self.stdout.write(f"    MFA Status:       ENABLED (RFC 6238 TOTP)")
            self.stdout.write(f"    MFA Secret:       {secret}")
            self.stdout.write(f"    Current TOTP:     {current_code} (Valid for ~30s)")
            if isinstance(plaintext_recovery_codes, list) and plaintext_recovery_codes and plaintext_recovery_codes[0] != "(Existing recovery codes active)":
                self.stdout.write(f"    Recovery Codes:   {', '.join(plaintext_recovery_codes)}")

        self.stdout.write(self.style.NOTICE("\n=== ALL SECURITY ACCOUNTS SUCCESSFULLY PREPARED ==="))
