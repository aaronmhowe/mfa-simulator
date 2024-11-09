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
        self.test_email = "user@wsu.edu"

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
        Tests when a new code is entered and store, the old code is overwritten.
        """
        self.mfa.store_mfa_code(self.test_email, "121212")
        code = self.mfa.database.get_code(self.test_email)
        self.assertEqual(code[0], "121212")
        self.mfa.store_mfa_code(self.test_email, "131313")
        new_code = self.mfa.database.get_code(self.test_email)
        self.assertEqual(new_code[0], "131313")


class EmailCodeTests(unittest.TestCase):
    """
    Test cases for the EmailCode class in totp_mfa.py
    """
    
    def credentials(self):
        """
        Initializes a test admin email, test user email, and test user password.
        """
        self.email = EmailCode()
        self.test_email = "user@wsu.edu"
        self.email.send_from = "admin.wsu.edu"
        self.email.password = "password"

    @patch('smtplib.SMTP_SSL')
    def sends_email(self, smtp):
        """
        Tests that an email is successfully sent to the user's email address.
        """
        send_email = self.email.send_to(self.test_email, "121212")
        self.assertTrue(send_email)
        smtp.return_value.send_message.assert_called_once()

    def invalid_receiving_email(self):
        """
        Tests that an error is thrown when there is an attempt to send an email to invalid address.
        """
        with self.assertRaises(ValueError):
            self.email.send_to("fake.email", "121212")
        

class DatabaseServerTests(unittest.TestCase):
    """
    Test cases for the DatabaseServer class in totp_mfa.py
    """
    
    def server(self):
        """
        Initializes the database and a test user email.
        """
        self.database = DatabaseServer()
        self.test_email = "user@wsu.edu"
        self.database.create_tables()

    def code_in_database(self):
        """
        Tests that verification codes are stored in the database.
        """
        self.database.store_code(self.test_email, "121212", datetime.now())
        is_stored = self.database.get_code(self.test_email)
        self.assertEqual(is_stored[0], "121212")
    
    def get_verification_code(self):
        """
        Tests fetching verification codes from the database.
        """
        self.database.store_code(self.test_email, "121212", datetime.now())
        code, _ = self.database.get_code(self.test_email)
        self.assertEqual(code, "121212")

    def get_nonexistent_code_error(self):
        """
        Tests that attempting to retrieve a verification that doesn't exist throws an error.
        """
        code = self.database.get_code("test@wsu.edu")
        self.assertIsNone(code)

    def code_is_used(self):
        """
        Tests that a verification code is successfully marked as used once a user submits it.
        """
        self.database.store_code(self.test_email, "121212", datetime.now())
        self.database.is_used(self.test_email, "121212")
        code = self.database.get_code(self.test_email)
        self.assertIsNone(code)

if __name__ == '__main__':
    unittest.main()