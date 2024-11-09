import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import sqlite3
from src.totp_mfa import TOTPMFA, EmailCode, DatabaseServer

class TOTPMFATests(unittest.TestCase):
    """
    Test cases for the TOTPMFA class in totp_mfa.py
    """

    def email(self):
        """
        Initializes a test email.
        """
        self.mfa = TOTPMFA()
        self.test_email = "test@wsu.edu"

    def code_length_is_six_ints(self):
        """
        Tests that the length of a verification code is 6 integers.
        """
        code = self.mfa.generate_code()
        self.assertEqual(len(code), 6)

    def code_is_unique(self):
        """
        Tests that a verification codes generate uniquely from one another.
        """
        generated_codes = [self.mfa.generate_code() for _ in range(5)]
        verification_codes = set(generated_codes)
        self.assertEqual(len(generated_codes), len(verification_codes))

    def sends_valid_code(self):
        """
        Tests that a valid verification is sent to a provided email address.
        """
        code = self.mfa.send_code(self.test_email)
        self.assertIsNotNone(code)
        self.assertEqual(len(code), 6)

    def send_to_invalid_email_throws_error(self):
        """
        Tests that an attempt to send a code to an invalid email throws an error.
        """
        with self.assertRaises(ValueError):
            self.mfa.send_code("fake.email")

    def sent_code_is_stored(self):
        """
        Tests that a verification code is stored in the code database upon being sent.
        """
        code = self.mfa.send_code(self.test_email)
        is_stored = self.mfa.database.get_code(self.test_email)
        self.assertIsNotNone(is_stored)

    def code_is_validated(self):
        """
        Tests that a code is successfully validated.
        """
        code = self.mfa.send_code(self.test_email)
        self.assertTrue(self.mfa.validate_code(self.test_email, code))

    def code_is_invalidated(self):
        """
        Tests that an incorrect code entry is rejected.
        """
        self.mfa.send_code(self.test_email)
        self.assertFalse(self.mfa.validate_code(self.test_email, "000000"))

    def code_is_expired(self):
        """
        Tests that an expired code entry is rejected.
        """
        with patch('time.time', return_value=datetime.now().timestamp() + 601):
            code = self.mfa.send_code(self.test_email)
            self.assertFalse(self.mfa.validate_code(self.test_email, code))

    def submitted_code_is_stored(self):
        """
        Tests that an entered code is stored in the database.
        """
        code = "654321"
        self.mfa.store_mfa_code(self.test_email, code)
        stored_code = self.mfa.database.get_code(self.test_email)
        self.assertIsNotNone(stored_code)

    def overwrite_stored_code(self):
        """
        Tests when a new code is entered and store, the old code is overwritten
        """
        self.mfa.store_mfa_code(self.test_email, "121212")
        code = self.mfa.database.get_code(self.test_email)
        self.assertEqual(code[0], "121212")
        self.mfa.store_mfa_code(self.test_email, "131313")
        new_code = self.mfa.database.get_code(self.test_email)
        self.assertEqual(new_code[0], "131313")

class EmailCodeTests(unittest.TestCase):
    pass

class DatabaseServer(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()