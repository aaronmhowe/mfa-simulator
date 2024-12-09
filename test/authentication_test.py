import unittest
from unittest.mock import Mock, patch
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from src.authentication import Authentication, AuthenticationDatabase

class AuthenticationTests(unittest.Testcase):
    """
    Test cases for the Authentication class in authentication.py
    """

    def setUp(self):
        """
        Initializing the test environment.
        """
        self.auth = Authentication()
        self.test_email = "user@wsu.edu"
        self.test_password = "TestCasePassword-321654"

    def test_register_account(self):
        """
        Tests that a user's account registers successfully with valid credentials.
        """
        registers = self.auth.register_account(self.test_email, self.test_password)
        self.assertTrue(registers)
        account = self.auth.database.get_credentials(self.test_email)
        self.assertIsNotNone(account)

    def test_register_account_invalid_email(self):
        """
        Tests that a user's account fails to register when providing an invalid email.
        """
        registers = self.auth.register_account("bademail", self.test_password)
        self.assertFalse(registers)
        
    def test_register_account_invalid_password(self):
        """
        Tests that a user's account fails to register when providing an invalid password.
        """
        registers1 = self.auth.register_account(self.test_email, "onlylowercase")
        self.assertFalse(registers1)
        registers2 = self.auth.register_account(self.test_email, "ONLYUPPERCASE")
        self.assertFalse(registers2)
        registers3 = self.auth.register_account(self.test_email, "1234567891011")
        self.assertFalse(registers3)
        registers4 = self.auth.register_account(self.test_email, "-_-_-_-_-_-_")
        self.assertFalse(registers4)
        registers5 = self.auth.register_account(self.test_email, "2-Short")
        self.assertFalse(registers5)

    def test_register_dup(self):
        """
        Tests that a user's account fails to register if the provided email is already in use.
        """
        self.auth.register_account(self.test_email, self.test_password)
        registers = self.auth.register_account(self.test_email, self.test_password)
        self.assertFalse(registers)

    def test_login(self):
        """
        Tests that a user successfully logs in upon inputting valid credentials.
        """
        self.auth.register_account(self.test_email, self.test_password)
        authenticates, token = self.auth.login(self.test_email, self.test_password)
        self.assertTrue(authenticates)
        self.assertIsNotNone(token)

    def test_invalid_login(self):
        """
        Tests that a login fails with invalid credentials.
        """
        authenticates, token = self.auth.login(self.test_email, "password")
        self.assertFalse(authenticates)
        self.assertIsNone(token)

    def test_mfa(self):
        """
        Tests that the user successfully sets up multifactor authentication.
        """
        self.auth.register_account(self.test_email, self.test_password)
        mfa, qr = self.auth.user_mfa(self.test_email)
        self.assertTrue(mfa)
        self.assertIsNotNone(qr)

    def test_logout(self):
        """
        Tests that the user can successfully logout of their account.
        """
        self.auth.register_account(self.test_email, self.test_password)
        _, token = self.auth.login(self.test_email, self.test_password)
        self.assertTrue(self.auth.logout(token))

    def tearDown(self):
        """
        Cleaning up the test environment.
        """
        with sqlite3.connect(self.auth.database.path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE email = ?", (self.test_email,))
            conn.commit()

class AuthenticationDatabaseTests(unittest.TestCase):
    """
    Test cases for the AuthenticationDatabase class in authentication.py
    """

    def setUp(self):
        """
        Initializing the test environment.
        """
        self.database = AuthenticationDatabase()
        self.test_email = "user@wsu.edu"
        self.test_password = "TestCasePassword-321654"
        self.passwd = bcrypt.hashpw(self.test_password.encode(), bcrypt.gensalt())

    def test_store_credentials(self):
        """
        Tests that a user's account is successfully stored in the database with password encrypted.
        """
        stored = self.database.store_credentials(self.test_email, self.passwd)
        self.assertTrue(stored)
        account = self.database.get_credentials(self.test_email)
        self.assertIsNotNone(account)
        self.assertEqual(account[0], self.test_email)

    def test_cannot_get_nonexistent_account(self):
        """
        Tests that an attempt to retrieve an account that doesn't exist, fails.
        """
        account = self.database.get_credentials("random@wsu.edu")
        self.assertIsNone(account)

    def tearDown(self):
        """
        Cleaning up the test environment.
        """
        with sqlite3.connect(self.database.path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE email = ?", (self.test_email,))
            conn.commit()


if __name__ == '__main__':
    unittest.main()