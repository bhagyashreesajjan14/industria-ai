import pyotp
import hashlib
from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from accounts.models import User, UserMFA, SecurityAuditLog
from machines.models import Machine
from manuals.models import Manual


class SecurityAuthenticationTests(TestCase):
    """
    Comprehensive Security & Strong Authentication Test Suite
    Specifically verifies all Round 1 Hackathon security criteria.
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
        self.admin_mfa = UserMFA.objects.create(
            user=self.admin,
            is_enabled=True,
            secret_key=pyotp.random_base32()
        )
        self.admin_recovery_codes = self.admin_mfa.generate_recovery_codes(8)
        self.admin_mfa.save()

        # Create Engineer
        self.engineer = User.objects.create_user(
            username='engineer_sec',
            email='engineer@sec.test',
            password='EngineerPassword123!',
            role=User.Role.ENGINEER
        )
        self.engineer_mfa = UserMFA.objects.create(
            user=self.engineer,
            is_enabled=True,
            secret_key=pyotp.random_base32()
        )
        self.engineer_recovery_codes = self.engineer_mfa.generate_recovery_codes(8)
        self.engineer_mfa.save()

        # Create Supervisor
        self.supervisor = User.objects.create_user(
            username='supervisor_sec',
            email='supervisor@sec.test',
            password='SupervisorPassword123!',
            role=User.Role.SUPERVISOR
        )
        self.supervisor_mfa = UserMFA.objects.create(
            user=self.supervisor,
            is_enabled=True,
            secret_key=pyotp.random_base32()
        )
        self.supervisor_recovery_codes = self.supervisor_mfa.generate_recovery_codes(8)
        self.supervisor_mfa.save()

        # Test machine for authorization tests
        self.machine = Machine.objects.create(
            machine_id='M-TEST1',
            model='TEST-1',
            name='Test Machine'
        )

    # =========================================================================
    # TEST 1: Admin credentials only work on Admin portal
    # =========================================================================
    def test_01_admin_portal_restrictions(self):
        # Admin on Admin portal -> Success (MFA prompt)
        res = self.client.post('/api/auth/login/', {
            'username': 'admin_sec',
            'password': 'AdminPassword123!',
            'portal': 'ADMIN'
        }, content_type='application/json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.json().get('mfa_required'))

        # Admin attempting Engineer portal -> 403 Forbidden
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
    # TEST 2: Engineer credentials only work on Engineer portal
    # =========================================================================
    def test_02_engineer_portal_restrictions(self):
        # Engineer on Engineer portal -> Success
        res = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.json().get('mfa_required'))

        # Engineer attempting Admin portal -> 403 Forbidden
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
    # TEST 3: Supervisor credentials only work on Supervisor portal
    # =========================================================================
    def test_03_supervisor_portal_restrictions(self):
        # Supervisor on Supervisor portal -> Success
        res = self.client.post('/api/auth/login/', {
            'username': 'supervisor_sec',
            'password': 'SupervisorPassword123!',
            'portal': 'SUPERVISOR'
        }, content_type='application/json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.json().get('mfa_required'))

        # Supervisor attempting Admin portal -> 403 Forbidden
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
    # TEST 4: Invalid passwords return generic HTTP 401 error (no username enumeration)
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

        # Messages must be identical to prevent enumeration
        self.assertEqual(res_nonexistent.json()['detail'], res_wrongpass.json()['detail'])

    # =========================================================================
    # TEST 5: Account lockout after 5 consecutive failed attempts
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

        # 6th attempt should return 403 ACCOUNT_LOCKED, even with CORRECT password
        res_locked = self.client.post('/api/auth/login/', {
            'username': 'lockout_victim',
            'password': 'CorrectPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(res_locked.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(res_locked.json().get('error'), 'ACCOUNT_LOCKED')

    # =========================================================================
    # TEST 6: MFA required before dashboard access
    # =========================================================================
    def test_06_mfa_required_before_dashboard(self):
        login_res = self.client.post('/api/auth/login/', {
            'username': 'engineer_sec',
            'password': 'EngineerPassword123!',
            'portal': 'ENGINEER'
        }, content_type='application/json')
        self.assertEqual(login_res.status_code, status.HTTP_200_OK)
        self.assertTrue(login_res.json().get('mfa_required'))

        # Verify session holds pending user ID, but is_mfa_verified is False
        session = self.client.session
        self.assertEqual(session.get('mfa_pending_user_id'), self.engineer.id)
        self.assertFalse(session.get('is_mfa_verified', False))

    # =========================================================================
    # TEST 7: Direct URL access without is_mfa_verified blocked by middleware
    # =========================================================================
    def test_07_mfa_gate_middleware_blocks_direct_access(self):
        # Force login the user without setting is_mfa_verified
        self.client.force_login(self.engineer)
        # Verify without setting session['is_mfa_verified']
        session = self.client.session
        session['is_mfa_verified'] = False
        session.save()

        # HTML Dashboard request must redirect to /mfa/verify/
        page_res = self.client.get('/engineer/')
        self.assertEqual(page_res.status_code, status.HTTP_302_FOUND)
        self.assertTrue(page_res.url.startswith('/mfa/verify/'))

        # API request must return 403 Forbidden with MFA_REQUIRED error code
        api_res = self.client.get('/api/machines/')
        self.assertEqual(api_res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(api_res.json().get('error'), 'MFA_REQUIRED')

    # =========================================================================
    # TEST 8: Engineer cannot access Admin endpoints
    # =========================================================================
    def test_08_engineer_cannot_access_admin_endpoints(self):
        self.client.force_login(self.engineer)
        session = self.client.session
        session['is_mfa_verified'] = True
        session.save()

        # Engineer cannot upload manuals
        res = self.client.post('/api/manuals/upload/', {
            'machine_id': 'M-TEST1',
            'title': 'Test Manual'
        })
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

        # Engineer cannot access audit logs
        res_logs = self.client.get('/api/auth/audit-logs/')
        self.assertEqual(res_logs.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # TEST 9: Supervisor cannot upload manuals
    # =========================================================================
    def test_09_supervisor_cannot_upload_manuals(self):
        self.client.force_login(self.supervisor)
        session = self.client.session
        session['is_mfa_verified'] = True
        session.save()

        res = self.client.post('/api/manuals/upload/', {
            'machine_id': 'M-TEST1',
            'title': 'Test Manual'
        })
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # TEST 10: Unauthenticated requests are rejected
    # =========================================================================
    def test_10_unauthenticated_requests_rejected(self):
        self.client.logout()

        # Protected API rejected with 401 Unauthorized or 403 Forbidden
        res_api = self.client.get('/api/machines/')
        self.assertIn(res_api.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

        # Protected page redirects to login
        res_page = self.client.get('/engineer/')
        self.assertEqual(res_page.status_code, status.HTTP_302_FOUND)
        self.assertTrue('/login/' in res_page.url)

    # =========================================================================
    # TEST 11: Logout clears session and resets MFA verification state
    # =========================================================================
    def test_11_logout_clears_session_completely(self):
        self.client.force_login(self.engineer)
        session = self.client.session
        session['is_mfa_verified'] = True
        session.save()

        logout_res = self.client.post('/api/auth/logout/')
        self.assertEqual(logout_res.status_code, status.HTTP_200_OK)

        # Session should be flushed
        self.assertFalse(self.client.session.get('is_mfa_verified', False))
        self.assertIsNone(self.client.session.get('_auth_user_id'))

        # Subsequent protected API request must fail (401 or 403)
        subsequent_res = self.client.get('/api/machines/')
        self.assertIn(subsequent_res.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    # =========================================================================
    # TEST 12: Recovery codes work and are single-use only
    # =========================================================================
    def test_12_mfa_single_use_recovery_codes(self):
        code_to_use = self.engineer_recovery_codes[0]

        # Stage session
        session = self.client.session
        session['mfa_pending_user_id'] = self.engineer.id
        session['is_mfa_verified'] = False
        session.save()

        # 1st use -> Accepted
        res = self.client.post('/api/auth/mfa/verify/', {
            'recovery_code': code_to_use
        }, content_type='application/json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.client.session.get('is_mfa_verified'))

        # Logout and stage session again to re-attempt using the same recovery code
        self.client.logout()
        session = self.client.session
        session['mfa_pending_user_id'] = self.engineer.id
        session['is_mfa_verified'] = False
        session.save()

        # 2nd use -> Rejected (Already used)
        res_reuse = self.client.post('/api/auth/mfa/verify/', {
            'recovery_code': code_to_use
        }, content_type='application/json')
        self.assertEqual(res_reuse.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res_reuse.json().get('error'), 'INVALID_RECOVERY_CODE')

    # =========================================================================
    # TEST 13: SecurityAuditLog records events without storing sensitive secrets
    # =========================================================================
    def test_13_audit_logging_no_sensitive_secrets(self):
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

        # Verify absolutely NO plaintext password or token appears in details
        self.assertNotIn('BadPassword999!', str(latest_log.details))
        self.assertNotIn('password', latest_log.details)
        self.assertNotIn('secret', latest_log.details)
        self.assertNotIn('token', latest_log.details)
