from django.core.management.base import BaseCommand
from accounts.models import User, SecurityAuditLog


class Command(BaseCommand):
    help = "Setup production security users (Admin, Engineer, Supervisor) with strong passwords and role verification."

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset passwords for existing users to defaults',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("=== CONFIGURING INDUSTRIA AI SECURITY ACCOUNTS ==="))

        users_config = [
            {
                "username": "admin",
                "email": "admin@industria.ai",
                "password": "Admin@Sec2026!",
                "role": User.Role.ADMIN,
                "portal": "/login/admin/",
                "dashboard": "/admin-dashboard/",
                "is_staff": True,
                "is_superuser": True,
            },
            {
                "username": "engineer",
                "email": "engineer@industria.ai",
                "password": "Engineer@Sec2026!",
                "role": User.Role.ENGINEER,
                "portal": "/login/engineer/",
                "dashboard": "/engineer/",
                "is_staff": False,
                "is_superuser": False,
            },
            {
                "username": "supervisor",
                "email": "supervisor@industria.ai",
                "password": "Supervisor@Sec2026!",
                "role": User.Role.SUPERVISOR,
                "portal": "/login/supervisor/",
                "dashboard": "/supervisor/",
                "is_staff": False,
                "is_superuser": False,
            },
        ]

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

            # Set password and reset lockouts
            user.set_password(item["password"])
            user.role = item["role"]
            user.is_staff = item["is_staff"]
            user.is_superuser = item["is_superuser"]
            user.reset_failed_logins()
            user.save()

            SecurityAuditLog.log(
                request=None,
                event_type=SecurityAuditLog.EventType.PASSWORD_CHANGED,
                user=user,
                portal=item["portal"],
                details={"action": "password_set_by_admin_command"}
            )

            status_str = "Created" if created else "Updated"
            self.stdout.write(self.style.SUCCESS(f"\n[+] {status_str} User: {username} ({item['role']})"))
            self.stdout.write(f"    Portal URL:       {item['portal']}")
            self.stdout.write(f"    Direct Dashboard: {item['dashboard']}")
            self.stdout.write(f"    Password:         {item['password']}")

        self.stdout.write(self.style.NOTICE("\n=== ALL SECURITY ACCOUNTS SUCCESSFULLY PREPARED ==="))
