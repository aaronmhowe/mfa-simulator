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
from .constants import DB_PATH, MFA_SETTINGS, AUTH_SETTINGS, DB_TABLES, INVALIDITY_RESPONSE


class TOTPMFA:
    """
    Central class for the functional logic of the Time-Based One-Time Password
    Multifactor Authentication software, that generates a QR verification code for a user.
    """

    def __init__(self):
        """
        Constructor for the TOTPMFA class - initializes the database.
        """
        self.database = MultifactorDatabase()
        self.verification_window = MFA_SETTINGS['VERIFICATION_WINDOW']
        self.input_limit = AUTH_SETTINGS['MAX_LOGIN_ATTEMPTS']
        self.timeout = AUTH_SETTINGS['LOGIN_TIMEOUT']

    def generate_totp(self, email: str) -> Tuple[str, str]:
        """
        Generates a secret key and uses it to construct a time-based one-time password
        as a QR Code.
        - Returns: the generated secret key and QR code
        """
        # throw an error if the user enters an email without an @ or . character
        if not '@' in email or not '.' in email:
            raise ValueError(INVALIDITY_RESPONSE['EMAIL'])
        
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        # constructing a provisioning URI to host the totp QR code
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name="MFA Simulator")
        print(f"Debug - Provisioning URI: {provisioning_uri}")

        qr_code = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=MFA_SETTINGS['QR_CODE_SIZE'], border=MFA_SETTINGS['QR_CODE_BORDER_SIZE'])
        qr_code.add_data(provisioning_uri)
        qr_code.make(fit=True)

        # designs and constructs the visual display of the generated QR code
        qr_image = qr_code.make_image(fill_color="black", back_color="white")
        qr_image = qr_image.resize((400, 400))
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG", optimize=False, quality=100)
        # converts the generated QR code to a base64 string through the buffer
        base64_conversion = base64.b64encode(buffer.getvalue()).decode()
        if not self.database.store_secret(email, secret):
            raise RuntimeError(INVALIDITY_RESPONSE['DATABASE'].format("Failed to store secret in database"))

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
            print(f"Debug - Validating Code: {code} with stored secret: [First 4 Chars: {secret[:4]}...]")

            if not secret:
                return False
            
            totp = pyotp.TOTP(secret)
            # fetch when the user input verification
            valid_code = totp.verify(code, valid_window=self.verification_window)
            print(f"Debug - Current Valid Code Would Be: {totp.now()}")
            
            # invalidate verification if it does not fall within the window
            if not valid_code:
                self.database.verification_attempts(email)
            else:
                self.database.delete_attempts(email)

            return valid_code
        
        except Exception as e:
            print(f"Debug - Exception in validate_code: {str(e)}")
            return False
    
    def is_blocked(self, email: str) -> bool:
        """
        Determines if the user has made too many verification attempts to add protection
        against brute-force attacks.
        - Param: email [str] -> User's email address.
        - Returns: True if the user has reached the maximum allowed attempts. False otherwise.
        """
        try:
            attempts = self.database.get_verification_attempts(email)
            # return true if the user's number of attempts is beyond the limit and time window
            if attempts >= self.input_limit:
                last_attempt = self.database.get_last_input_time(email)
                if last_attempt is not None:
                    stopwatch = time.time() - last_attempt
                    if stopwatch < self.timeout:
                        return True
                    
                self.database.delete_attempts(email) 
            return False
        except Exception as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return False

    def generate_new_totp(self, email: str) -> Tuple[str, str]:
        """
        Generates a new secret key and totp code, and rendering the previously generated code void.
         - Param: email [str] -> User's email address.
        """
        return self.generate_totp(email)

    def set_verification_window(self, window: int) -> None:
        """
        Sets a timer for verification input, cancelling verification if the user fails to provide
        successful input before the timer runs out.
        - Param: window [int] -> Verification window size.
        """
        # below 0 is invalid, reset the window size
        if (window < 0):
            raise ValueError(INVALIDITY_RESPONSE['DATABASE'].format("Error occurred setting the verification window size: size cannot be negative."))
        self.verification_window = window

    def get_window(self) -> int:
        """
        Fetches the input verification time window.
        - Returns: The window.
        """
        return self.verification_window


class MultifactorDatabase:
    """
    Class for the functional logic of the local verification code database. Handles
    the storing and fetching of verification codes.
    """

    def __init__(self):
        """
        Constructor for the DatabaseServer class - setting up a path to a
        SQLite database.
        """
        self.path: str = DB_PATH['MFA']
        self.create_mfa_tables()

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
                cursor.execute(f"""
                    INSERT OR REPLACE INTO {DB_TABLES['TOTP_SECRETS']} (email, secret)
                    VALUES (?, ?)
                """, (email, secret))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
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
                cursor.execute(f"SELECT secret FROM {DB_TABLES['TOTP_SECRETS']} WHERE email = ?", (email,))
                key = cursor.fetchone()
                return key[0] if key else None
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
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
                cursor.execute(f"DELETE FROM {DB_TABLES['TOTP_SECRETS']} WHERE email = ?", (email,))
                conn.commit()
                deleted = cursor.rowcount > 0
                return deleted
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return False

    def create_mfa_tables(self) -> None:
        """
        Constructs database tables in the mfa database.
        """
        # creating a connection to the SQLite database
        try:
            with sqlite3.connect(self.path) as conn:
                # storing generated secret keys
                cursor = conn.cursor()
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {DB_TABLES['TOTP_SECRETS']} (
                        email TEXT PRIMARY KEY, 
                        secret TEXT NOT NULL, 
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # storing verification attempts
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {DB_TABLES['VERIFICATION_ATTEMPTS']} (
                        email TEXT PRIMARY KEY,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE_ERROR'].format(str(e)))
            raise

    def verification_attempts(self, email: str) -> bool:
        """
        Tracks each verification attempt made by a user and stores them in the database.
        - Param: email [str] -> User's email address.
        - Returns: True if an attempt was successfully tracked and stored in the database.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                # store verification attempt
                cursor.execute(f"""
                    UPDATE {DB_TABLES['VERIFICATION_ATTEMPTS']}
                    SET attempts = COALESCE(attempts, 0) + 1,
                        last_attempt = CURRENT_TIMESTAMP
                    WHERE email = ?
                """, (email,))

                if cursor.rowcount == 0:
                    cursor.execute(f"""
                        INSERT INTO {DB_TABLES['VERIFICATION_ATTEMPTS']} (email, attempts, last_attempt)
                        VALUES (?, 1, CURRENT_TIMESTAMP)
                    """, (email,))

                conn.commit()
                return True
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return False

    def get_verification_attempts(self, email: str) -> int:
        """
        Fetches failed verification attempts stored in the base.
        - Param: email [str] -> User's email address.
        - Returns: Count of verification attempts by the user.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"""
                    SELECT attempts FROM {DB_TABLES['VERIFICATION_ATTEMPTS']} 
                    WHERE email = ?
                """, (email,))
                # retrieve the result of executing the sql query
                attempts = cursor.fetchone()
                return attempts[0] if attempts else 0
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return 0

    def delete_attempts(self, email: str) -> bool:
        """
        Clears the database of stored verification attempts.
        - Param: email [str] -> User's email address.
        - Returns: True if the verification attempst have cleared.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"DELETE FROM {DB_TABLES['VERIFICATION_ATTEMPTS']} WHERE email = ?", (email,))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return False

    def get_last_input_time(self, email: str) -> Optional[float]:
        """
        Fetches the point within the time window that the user last entered a verification attempt.
        - Param: email [str] -> User's email address.
        - Returns: The time at last verification attempt.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT last_attempt FROM {DB_TABLES['VERIFICATION_ATTEMPTS']} WHERE email = ?", (email,))
                attempt = cursor.fetchone()
                # at most recent verification attempt, retrieve timestamp
                if attempt and attempt[0]:
                    input_time = datetime.strptime(attempt[0], '%Y-%m-%d %H:%M:%S')
                    return input_time.timestamp()
                return None
        except sqlite3.Error as e:
            print(INVALIDITY_RESPONSE['DATABASE'].format(str(e)))
            return None