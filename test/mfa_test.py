import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import sqlite3
import sqlite3
import base64
import re
from src.totp_mfa import TOTPMFA, DatabaseServer


class TOTPMFATests(unittest.TestCase):
    """
    Test cases for the TOTPMFA class in totp_mfa.py
    """

    def setUp(self):
        """
        Initializing the test environment.
        """
        self.mfa = TOTPMFA()
        self.test_email = "user@wsu.edu"
        self.mfa.database.delete_secret(self.test_email)

    def test_generates_secret(self):
        """
        Tests that a secret key is successfully generated.
        """
        secret, _ = self.mfa.generate_totp(self.test_email)
        self.assertTrue(all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in secret))
        self.assertEqual(len(secret), 32)

    def test_generates_qr_code(self):
        """
        Tests that a valid QR code is successfully generated.
        """
        _, qr_code = self.mfa.generate_totp(self.test_email)

        try:
            code = base64.b64decode(qr_code)
            self.assertTrue(code.startswith(b'\x89PNG'))
        except Exception:
            self.fail("Invalid QR Code.")

    def test_stores_secret_key(self):
        """
        Tests that the generated secret key is stored in the database.
        """
        secret, _ = self.mfa.generate_totp(self.test_email)
        secret_key = self.mfa.database.get_secret(self.test_email)
        self.assertEqual(secret, secret_key)
    
    def test_invalid_qr_code_fails(self):
        """
        Tests that an invalid passcode is rejected.
        """
        self.mfa.generate_totp(self.test_email)
        code = "000000"
        self.assertFalse(self.mfa.validate_code(self.test_email, code))

    def test_block_user_attempts(self):
        """
        Tests that verification attempts are blocked if the user has made too many previous attempts.
        """
        self.mfa.generate_totp(self.test_email)
        # three failed verification attempts
        for _ in range(3):
            self.mfa.validate_code(self.test_email, "000000")

        self.assertTrue(self.mfa.is_blocked(self.test_email))
        self.assertFalse(self.mfa.validate_code(self.test_email, "000000"))

    def test_pass_verification_timeout(self):
        """
        Tests that verification input is accepted when entered within the set time window.
        """
        self.mfa.generate_totp(self.test_email)
        limit = self.mfa.time_limit()
        self.mfa.verification_timeout(5)
        self.assertEqual(self.mfa.time_limit(), 5)
        self.mfa.time_limit(limit)

    
class DatabaseServerTests(unittest.TestCase):
    """
    Test cases for the DatabaseServer class in totp_mfa.py
    """

    def setUp(self):
        """
        Initializing the test environment.
        """
        self.database = DatabaseServer()
        self.test_email = "user@wsu.edu"
        self.test_secret = "SDERQ8UITGVC2MOF"
        self.database.delete_secret(self.test_email)
    
    def test_store_secret_key(self):
        """
        Tests that the secret key is stored in the database.
        """
        self.assertTrue(self.database.store_secret(self.test_email, self.test_secret))
        secret = self.database.get_secret(self.test_email)
        self.assertEqual(secret, self.test_secret)

    def test_secret_deletes(self):
        """
        Tests that deleting a secret key is successful.
        """
        self.database.store_secret(self.test_email, self.test_secret)
        self.assertTrue(self.database.delete_secret(self.test_email))
        self.assertIsNone(self.database.get_secret(self.test_email))

    def test_tracks_attempts(self):
        """
        Tests that failed attempts to pass verification are being properly tracked and stored
        in the database.
        """
        self.assertTrue(self.database.verification_attempts(self.test_email))
        attempts = self.database.get_verification_attempts(self.test_email)
        self.assertEqual(attempts, 1)

    def tearDown(self):
        """
        Cleaning up the test environment.
        """
        self.database.delete_secret(self.test_email)


if __name__ == '__main__':
    unittest.main()