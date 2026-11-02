from django.test import TestCase, Client
from rest_framework import status
from accounts.models import User, SecurityAuditLog
from machines.models import Machine


class SecurityAuthenticationTests(TestCase):
    """
    Comprehensive Security & Direct Authentication Test Suite:
    - Direct login without MFA/OTP screens for Admin, Engineer, and Supervisor.
    - Strict server-side role verification for each portal.
    - Account lockout after 5 consecutive failed attempts.
    - Username enumeration protection (uniform error message).
    - Session key cycling and session flush on logout.
    - Role-based authorization and security audit logging.
    """

    def setUp(self):
        self.client = Client()

        # Create Admin
        self.admin = User.objects.create_user(
            username='admin_sec',
            email='admin@sec.test',
            password='AdminPassword123!',
            role=User.Role.ADMIN,
            is_staff=True,
            is_superuser=True
        )

        # Create Engineer
        self.engineer = User.objects.create_user(
            username='engineer_sec',
            email='engineer@sec.test',
            password='EngineerPassword123!',
            role=User.Role.ENGINEER
        )

        # Create Supervisor
        self.supervisor = User.objects.create_user(
            username='supervisor_sec',
            email='supervisor@sec.test',
            password='SupervisorPassword123!',
            role=User.Role.SUPERVISOR
        )

        # Test machine for authorization tests
        self.machine = Machine.objects.create(
            machine_id='M-TEST1',
            model='TEST-1',
            name='Test Machine'
        )

    # =========================================================================
    # TEST 1: Admin Direct Login and Portal Restrictions
    # =========================================================================
    def test_01_admin_direct_login_and_portal_restrictions(self):
        # Admin on Admin portal -> Direct Success, redirect to /admin-dashboard/
        res = self.client.post('/api/auth/login/', {
            'username': 'admin_sec',
            'password': 'AdminPassword123!',
            'portal': 'ADMIN'
        }, content_type='application/json')

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.json().get('redirect_url'), '/admin-dashboard/')
        self.assertNotIn('mfa_required', res.json())
        self.assertNotIn('mfa_setup_required', res.json())

        # Verify authenticated session can directly access /admin-dashboard/
        dashboard_res = self.client.get('/admin-dashboard/')
        self.assertEqual(dashboard_res.status_code, status.HTTP_200_OK)

        # Admin attempting Engineer portal -> 403 Forbidden
        self.client.logout()
        res_eng = self.client.post('/api/auth/login/', {
            'username': 'admin_sec',
            'password': 'AdminPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_eng.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_eng.json().get('error'), 'PORTAL_ROLE_MISMATCH')

        # Admin attempting Supervisor portal -> 403 Forbidden
        res_sup = self.client.post('/api/auth/login/', {
            'username': 'admin_sec',
            'password': 'AdminPassword123!',
            'portal': 'SUPERVISOR'
        }, content_type='application/json')
        self.assertEqual(res_sup.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_sup.json().get('error'), 'PORTAL_ROLE_MISMATCH')

    # =========================================================================
    # TEST 2: Engineer Direct Login and Portal Restrictions
    # =========================================================================
    def test_02_engineer_direct_login_and_portal_restrictions(self):
        # Engineer on Engineer portal -> Direct Success, redirect to /engineer/
        res = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.json().get('redirect_url'), '/engineer/')
        self.assertNotIn('mfa_required', res.json())
        self.assertNotIn('mfa_setup_required', res.json())

        # Verify authenticated session can directly access /engineer/
        dashboard_res = self.client.get('/engineer/')
        self.assertEqual(dashboard_res.status_code, status.HTTP_200_OK)

        # Engineer attempting Admin portal -> 403 Forbidden
        self.client.logout()
        res_admin = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'ADMIN'
        }, content_type='application/json')
        self.assertEqual(res_admin.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_admin.json().get('error'), 'PORTAL_ROLE_MISMATCH')

        # Engineer attempting Supervisor portal -> 403 Forbidden
        res_sup = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'SUPERVISOR'
        }, content_type='application/json')
        self.assertEqual(res_sup.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_sup.json().get('error'), 'PORTAL_ROLE_MISMATCH')

    # =========================================================================
    # TEST 3: Supervisor Direct Login and Portal Restrictions
    # =========================================================================
    def test_03_supervisor_direct_login_and_portal_restrictions(self):
        # Supervisor on Supervisor portal -> Direct Success, redirect to /supervisor/
        res = self.client.post('/api/auth/login/', {
            'username': 'supervisor_sec',
            'password': 'SupervisorPassword123!',
            'portal': 'SUPERVISOR'
        }, content_type='application/json')

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.json().get('redirect_url'), '/supervisor/')
        self.assertNotIn('mfa_required', res.json())
        self.assertNotIn('mfa_setup_required', res.json())

        # Verify authenticated session can directly access /supervisor/
        dashboard_res = self.client.get('/supervisor/')
        self.assertEqual(dashboard_res.status_code, status.HTTP_200_OK)

        # Supervisor attempting Admin portal -> 403 Forbidden
        self.client.logout()
        res_admin = self.client.post('/api/auth/login/', {
            'username': 'supervisor_sec',
            'password': 'SupervisorPassword123!',
            'portal': 'ADMIN'
        }, content_type='application/json')
        self.assertEqual(res_admin.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_admin.json().get('error'), 'PORTAL_ROLE_MISMATCH')

        # Supervisor attempting Engineer portal -> 403 Forbidden
        res_eng = self.client.post('/api/auth/login/', {
            'username': 'supervisor_sec',
            'password': 'SupervisorPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_eng.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_eng.json().get('error'), 'PORTAL_ROLE_MISMATCH')

    # =========================================================================
    # TEST 4: Invalid Passwords Return Generic HTTP 401 Error
    # =========================================================================
    def test_04_invalid_credentials_generic_message(self):
        # Non-existent user
        res_nonexistent = self.client.post('/api/auth/login/', {
            'username': 'ghost_user_99',
            'password': 'WrongPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_nonexistent.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_nonexistent.json().get('detail'), 'Invalid username or password.')

        # Real user with wrong password
        res_wrongpass = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'WrongPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_wrongpass.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(res_wrongpass.json().get('detail'), 'Invalid username or password.')

        # Messages must be identical to prevent username enumeration
        self.assertEqual(res_nonexistent.json()['detail'], res_wrongpass.json()['detail'])

    # =========================================================================
    # TEST 5: Account Lockout After 5 Consecutive Failed Attempts
    # =========================================================================
    def test_05_account_lockout_after_five_failed_attempts(self):
        user = User.objects.create_user(
            username='lockout_victim',
            password='CorrectPassword123!',
            role=User.Role.ENGINEER
        )

        for attempt in range(5):
            res = self.client.post('/api/auth/login/', {
                'username': 'lockout_victim',
                'password': 'BadPassword',
                'portal': 'ENGINEER'
            }, content_type='application/json')
            self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertTrue(user.is_locked)

        # 6th attempt should return 403 ACCOUNT_LOCKED even with CORRECT password
        res_locked = self.client.post('/api/auth/login/', {
            'username': 'lockout_victim',
            'password': 'CorrectPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_locked.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_locked.json().get('error'), 'ACCOUNT_LOCKED')

    # =========================================================================
    # TEST 6: Engineer Cannot Access Admin Dashboard or Endpoints
    # =========================================================================
    def test_06_engineer_cannot_access_admin_dashboard_or_endpoints(self):
        self.client.force_login(self.engineer)

        # Engineer accessing /admin-dashboard/ redirects to /engineer/
        page_res = self.client.get('/admin-dashboard/')
        self.assertEqual(page_res.status_code, status.HTTP_302_FOUND)
        self.assertEqual(page_res.url, '/engineer/')

        # Engineer cannot upload manuals
        res = self.client.post('/api/manuals/upload/', {
            'machine_id': 'M-TEST1',
            'title': 'Test Manual'
        })
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

        # Engineer cannot access security audit logs
        res_logs = self.client.get('/api/auth/audit-logs/')
        self.assertEqual(res_logs.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # TEST 7: Supervisor Cannot Upload Manuals
    # =========================================================================
    def test_07_supervisor_cannot_upload_manuals(self):
        self.client.force_login(self.supervisor)

        res = self.client.post('/api/manuals/upload/', {
            'machine_id': 'M-TEST1',
            'title': 'Test Manual'
        })
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # TEST 8: Unauthenticated Requests Are Rejected
    # =========================================================================
    def test_08_unauthenticated_requests_rejected(self):
        self.client.logout()

        # Protected API rejected with 401/403
        res_api = self.client.get('/api/machines/')
        self.assertIn(res_api.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

        # Protected page redirects to login
        res_page = self.client.get('/engineer/')
        self.assertEqual(res_page.status_code, status.HTTP_302_FOUND)
        self.assertTrue('/login/' in res_page.url)

    # =========================================================================
    # TEST 9: Logout Clears Session Completely
    # =========================================================================
    def test_09_logout_clears_session_completely(self):
        self.client.force_login(self.engineer)

        logout_res = self.client.post('/api/auth/logout/')
        self.assertEqual(logout_res.status_code, status.HTTP_200_OK)

        # Session should be flushed
        self.assertIsNone(self.client.session.get('_auth_user_id'))

        # Subsequent protected API request must fail
        subsequent_res = self.client.get('/api/machines/')
        self.assertIn(subsequent_res.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    # =========================================================================
    # TEST 10: SecurityAuditLog Records Events Without Leaking Passwords
    # =========================================================================
    def test_10_audit_logging_no_sensitive_secrets(self):
        initial_log_count = SecurityAuditLog.objects.count()

        # Trigger login failure
        self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'BadPassword999!',
            'portal': 'ENGINEER'
        }, content_type='application/json')

        # Check that log was created
        self.assertGreater(SecurityAuditLog.objects.count(), initial_log_count)
        latest_log = SecurityAuditLog.objects.first()

        self.assertEqual(latest_log.event_type, SecurityAuditLog.EventType.LOGIN_FAILED)
        self.assertEqual(latest_log.username_attempted, 'engineer_sec')

        # Verify absolutely NO plaintext password appears in details
        self.assertNotIn('BadPassword999!', str(latest_log.details))
        self.assertNotIn('password', latest_log.details)

    # =========================================================================
    # TEST 11: Session Fixation Protection via Session Key Rotation
    # =========================================================================
    def test_11_session_key_rotation_on_login(self):
        # Initial session
        self.client.get('/login/')
        initial_session_key = self.client.session.session_key

        # Perform login
        self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')

        new_session_key = self.client.session.session_key
        # Key must change to prevent session fixation
        self.assertNotEqual(initial_session_key, new_session_key)

    # =========================================================================
    # TEST 12: Locked User Cannot Access Authenticated Pages Via Middleware
    # =========================================================================
    def test_12_locked_user_session_terminated_by_middleware(self):
        self.client.force_login(self.engineer)
        # Lock user
        self.engineer.record_failed_login(max_attempts=1, lockout_minutes=15)
        self.assertTrue(self.engineer.is_locked)

        # Middleware intercepts and redirects to /login/?error=locked
        page_res = self.client.get('/engineer/')
        self.assertEqual(page_res.status_code, status.HTTP_302_FOUND)
        self.assertTrue('/login/?error=locked' in page_res.url)

    # =========================================================================
    # TEST 13: Central Portal Gateway Login Flows
    # =========================================================================
    def test_13_central_login_redirect_flows(self):
        # Admin via central portal
        res_admin = self.client.post('/api/auth/login/', {
            'username': 'admin_sec',
            'password': 'AdminPassword123!'
        }, content_type='application/json')
        self.assertEqual(res_admin.status_code, status.HTTP_200_OK)
        self.assertEqual(res_admin.json().get('redirect_url'), '/admin-dashboard/')

        self.client.logout()

        # Engineer via central portal
        res_eng = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!'
        }, content_type='application/json')
        self.assertEqual(res_eng.status_code, status.HTTP_200_OK)
        self.assertEqual(res_eng.json().get('redirect_url'), '/engineer/')

        self.client.logout()

        # Supervisor via central portal
        res_sup = self.client.post('/api/auth/login/', {
            'username': 'supervisor_sec',
            'password': 'SupervisorPassword123!'
        }, content_type='application/json')
        self.assertEqual(res_sup.status_code, status.HTTP_200_OK)
        self.assertEqual(res_sup.json().get('redirect_url'), '/supervisor/')
