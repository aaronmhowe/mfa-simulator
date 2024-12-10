import unittest
from unittest.mock import Mock, patch
from src.application import ApplicationViews, Application
from src.authentication import Authentication

class ApplicationTests(unittest.TestCase):
    """
    Test cases for the Application class in application.py
    """

    def setUp(self):
        """
        Initializing the test environment.
        """
        self.app = Application()
        self.test_email = "user@wsu.edu"
        self.test_password = "TestCasePassword-321654"
        self.test_token = "test_token"
        self.test_qr = "test_qr"
        self.app.auth = Mock(spec=Authentication)

    def test_start_up_view(self):
        """
        Tests that the view of the application opens with the correct state upon app execution.
        """
        self.assertEqual(self.app.get_view(), ApplicationViews.startup_view)
        self.assertIsNone(self.app.get_user())
        self.assertIsNone(self.app.token)

    def test_view_change(self):
        """
        Tests that a switch to a new view is successful.
        """
        self.app.set_view(ApplicationViews.login_view)
        self.assertEqual(self.app.get_view(), ApplicationViews.login_view)

    def test_registration_updates(self):
        """
        Tests that the registration process is correct and results in the proper view updates.
        """
        # forces a successful registration
        self.app.auth.register_account.return_value = True
        register, message = self.app.app_registration(self.test_email, self.test_password, self.test_password)
        self.assertTrue(register)
        self.assertEqual(self.app.get_user(), self.test_email)
        self.assertEqual(self.app.get_view(), ApplicationViews.mfa_setup_view)
        self.app.auth.register_account.assert_called_once()

    def test_invalid_password_updates(self):
        """
        Tests that an invalid password entry results in the proper application view update.
        """
        register, message = self.app.app_registration(self.test_email, self.test_password, "NotTheSamePassword-12324")
        self.assertFalse(register)
        self.assertIn("Password confirmation does not match!", message)
        self.app.auth.register_account.assert_not_called()

    def test_login_updates(self):
        """
        Tests that the login process is correct and results in the proper view updates.
        """
        # forces a successful login and administers a login token
        self.app.auth.login.return_value = (True, self.test_token)
        login, message = self.app.app_login(self.test_email, self.test_password)
        self.assertTrue(login)
        self.assertEqual(self.app.get_user(), self.test_email)
        self.assertEqual(self.app.token, self.test_token)
        # opens mfa verification page for mfa code verification page
        self.assertEqual(self.app.get_view(), ApplicationViews.mfa_verification_view)

    def test_invalid_login_updates(self):
        """
        Tests that invalid login credentials results in the proper application view update.
        """
        self.app.auth.login.return_value = (False, None)
        login = self.app.app_login(self.test_email, self.test_password)
        self.assertFalse(login)
        # does not retrieve account or login token
        self.assertIsNone(self.app.get_user())
        self.assertIsNone(self.app.token)

    def test_mfa_setup_updates(self):
        """
        Tests that multifactor authentication set-up process is correct and results in the proper view updates.
        """
        self.app.user = self.test_email
        self.app.auth.user_mfa.return_value = (True, self.test_qr)
        mfa, qr = self.app.app_user_mfa()
        self.assertTrue(mfa)
        self.assertEqual(qr, self.test_qr)
        self.app.auth.user_mfa.assert_called_once_with(self.test_email)

    def test_mfa_verification_updates(self):
        """
        Tests that multifactor authentication code entry results in the proper view updates.
        """
        self.app.user = self.test_email
        self.app.auth.verify_authentication_code.return_value = (True, "Code Accepted.")
        code = self.app.app_validate_code("123456")
        self.assertTrue(code)
        # launches into application home page
        self.assertEqual(self.app.get_view(), ApplicationViews.main_view)

    def test_invalid_code_updates(self):
        """
        Tests that invalid code entry for mfa authentication results in the proper view updates.
        """
        self.app.user = self.test_email
        self.app.token = self.test_token
        self.app.auth.verify_authentication_code.return_value = (False, "Invalid Code Input!")
        code = self.app.app_validate_code("000000")
        self.assertFalse(code)
        self.assertEqual(self.app.get_view(), ApplicationViews.mfa_verification_view)

    def test_logout_updates(self):
        """
        Tests that a user logs out upon invokation and results in the proper state change and view updates.
        """
        self.app.user = self.test_email
        self.app.token = self.test_token
        self.app.view = ApplicationViews.main_view
        self.app.auth.logout.return_value = True
        logout = self.app.app_logout()
        self.assertTrue(logout)
        self.assertEqual(self.app.get_view(), ApplicationViews.startup_view)
        self.assertIsNone(self.app.get_user())
        self.assertIsNone(self.app.token)

    def test_email_validation_updates(self):
        """
        Tests that email input results in the proper update.
        """
        self.app.auth.is_valid_email.side_effect = [True, False]
        # valid email input
        email = self.app.app_validate_email(self.test_email)
        self.assertTrue(email)
        # invalid email input
        email = self.app.app_validate_email("Email is either invalid or does not exist.")
        self.assertFalse(email)

    def test_password_validation_updates(self):
        """
        Tests that password input results in the proper update.
        """
        self.app.auth.is_valid_password.side_effect = [True, False]
        password = self.app.app_validate_password(self.test_password)
        self.assertTrue(password)
        password = self.app.app_validate_password("""
                                                  Invalid Password: Must be at least 12 characters in length, have at least one lowercase,
                                                  one uppercase, one special character, and one number!)
                                                  """)
        self.assertFalse(password)

if __name__ == '__main__':
    unittest.main()
