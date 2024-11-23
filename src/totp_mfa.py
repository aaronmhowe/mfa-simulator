import pyotp
import time
from typing import List, Tuple, Optional
import sqlite3
from datetime import datetime, timedelta
import qrcode
from PIL import Image
import io
import base64
import secrets
import string


class TOTPMFA:
    """
    Central class for the functional logic of the Time-Based One-Time Password
    Multifactor Authentication software, that generates a QR verification code for a user.
    """

    INPUT_LIMIT = 3
    TIMEOUT = 60
    VERIFICATION_WINDOW = 1

    def __init__(self):
        """
        Constructor for the TOTPMFA class - initializes the database.
        """
        self.database = DatabaseServer()
        self.verification_window = self.VERIFICATION_WINDOW

    def generate_totp(self, email: str) -> Tuple[str, str]:
        """
        Generates a secret key and uses it to construct a time-based one-time password
        as a QR Code.
        - Returns: the generated secret key and QR code
        """
        # throw an error if the user enters an email without an @ or . character
        if not '@' in email or not '.' in email:
            raise ValueError("Invalid Format.")
        
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        # constructing a provisioning URI to host the totp QR code
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name="MFA Simulator")

        qr_code = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr_code.add_data(provisioning_uri)
        qr_code.make(fit=True)

        # designs and constructs the visual display of the generated QR code
        qr_image = qr_code.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG")
        # converts the generated QR code to a base64 string through the buffer
        base64_conversion = base64.b64encode(buffer.getvalue()).decode()
        if not self.database.store_secret(email, secret):
            raise RuntimeError("Failed to store secret in database")

        return secret, base64_conversion
    
    def validate_code(self, email: str, code: str) -> bool:
        """
        Validates the generated code.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Code provided by the user.
        - Returns: True if the provided code from the user is valid.
        """
        try:
            # invalidate verification if the user has made too many attempts
            if self.is_blocked(email):
                return False

            secret = self.database.get_secret(email)

            if not secret:
                return False
            
            totp = pyotp.TOTP(secret)
            # fetch when the user input verification
            valid_code = totp.verify(code, valid_window=self.verification_window)
            
            # invalidate verification if it does not fall within the window
            if not valid_code:
                self.database.verification_attempts(email)

            return totp.verify(code)
        
        except Exception:
            return False
    
    def is_blocked(self, email: str) -> bool:
        """
        Determines if the user has made too many verification attempts to add protection
        against brute-force attacks.
        - Param: email [str] -> User's email address.
        - Returns: True if the user has reached the maximum allowed attempts. False otherwise.
        """
        attempts = self.database.get_verification_attempts(email)
        # return true if the user's number of attempts is beyond the limit and time window
        if attempts >= self.INPUT_LIMIT:
            last = self.database.get_input_time(email)
            if last and (time.time() - last) < self.TIMEOUT:
                return True
            
        return False

    def verification_window(self, window: int) -> None:
        """
        Sets a timer for verification input, cancelling verification if the user fails to provide
        successful input before the timer runs out.
        - Param: window [int] -> Verification window size.
        """
        # below 0 is invalid, reset the window size
        if (window < 0):
            window = self.verification_window
        window = self.verification_window

    def get_window(self) -> int:
        """
        Fetches the input verification time window.
        - Returns: The window.
        """
        return self.verification_window(10)


class DatabaseServer:
    """
    Class for the functional logic of the local verification code database. Handles
    the storing and fetching of verification codes.
    """

    def __init__(self):
        """
        Constructor for the DatabaseServer class - setting up a path to a
        SQLite database.
        """
        self.path: str = "secrets.db"
        self.create_tables()

    def store_secret(self, email: str, secret: str) -> bool:
        """
        Stores a generated verification code in the database.
        - Param: email [str] -> User's email address.
        - Param: secret [str] -> Generated secret key.
        - Returns: True if the secret has been stored.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO totp_secrets (email, secret)
                    VALUES (?, ?)
                """, (email, secret))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"Database error in store_secret: {e}")
            return False

    def get_secret(self, email: str) -> Optional[str]:
        """
        Fetches the secret key for a user via their associated email address.
        - Param: email [str] -> User's email address.
        - Returns: The secret key if it exists.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT secret FROM totp_secrets WHERE email = ?", (email,))
                key = cursor.fetchone()
                return key[0] if key else None
        except sqlite3.Error as e:
            print(f"Database error in get_secret: {e}")
            return None

    def delete_secret(self, email: str) -> bool:
        """
        Deletes a user's secret key.
        - Param: email [str] -> User's email address.
        - Returns: True if the key is successfully deleted.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM totp_secrets WHERE email = ?", (email,))
                conn.commit()
                deleted = cursor.rowcount > 0
                return deleted
        except sqlite3.Error as e:
            print(f"Database error in delete_secret: {e}")
            return False

    def create_tables(self) -> None:
        """
        Constructs database tables.
        """
        try:
            # creating a connection to the SQLite database
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS totp_secrets (
                        email TEXT PRIMARY KEY, 
                        secret TEXT NOT NULL, 
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(f"Error Occurred Constructing Database Tables: {e}")
            raise

    def verification_attempts(self, email: str) -> bool:
        """
        Tracks each verification attempt made by a user and stores them in the database.
        - Param: email [str] -> User's email address.
        - Returns: True if an attempt was successfully tracked and stored in the database.
        """
        pass

    def get_verification_attempts(self, email: str) -> bool:
        """
        Fetches failed verification attempts stored in the base.
        - Param: email [str] -> User's email address.
        - Returns: True if at least one failed attempt is found. False otherwise.
        """
        pass

    def get_input_time(self, email: str) -> int:
        """
        Fetches the point within the time window that the user last entered a verification attempt.
        - Param: email [str] -> User's email address.
        - Returns: The time at last verification attempt.
        """
        pass