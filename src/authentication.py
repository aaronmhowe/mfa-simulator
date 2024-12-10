import sqlite3
from typing import Optional, Tuple, Dict
from datetime import datetime, timedelta
import secrets
import bcrypt
import re
from .totp_mfa import TOTPMFA

class Authentication:
    """
    Manages logic for user registration, login, and credential authentication using the multifactor
    authentication implementation from class TOTPMFA.
    """

    def __init__(self):
        """
        Constructor for the Authentication class.
        """
        self.database = AuthenticationDatabase()
        self.mfa = TOTPMFA()
        # tracking accounts that are actively logged in
        self.logged_in_accounts: Dict[str, datetime] = {}

    def register_account(self, email: str, password: str) -> bool:
        """
        Registers an account based on user-provided email and password credentials.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True if successfully registered.
        """
        try:
            # check if provided email is valid format
            if not self.is_valid_email(email):
                return False
            
            # check if proposed password meets minimum requirements
            if not self.is_valid_password(password):
                return False
            
            # check if email already in use
            if self.database.get_credentials(email):
                return False
            
            # encrypt user password
            pw_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            passwd = bcrypt.hashpw(pw_bytes, salt)
            # if provided credentials are valid, store in database
            stored = self.database.store_credentials(email, passwd)
            return stored
        except Exception as e:
            print(f"Error occurred when trying to register account: {e}")
            return False

    def login(self, email: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Logs a user into the application by evaluating the user's login credentials,
        and attaches a session token to the user upon successful authentication that serves 
        as an identity.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True upon successful authentication, with a session token.
        """
        try:
            account = self.database.get_credentials(email)
            # check if credentials don't match existing
            if not account:
                print("Account not found")
                return False, None
            
            # check if provided password matches hashed password
            stored = account[1]
            try:
                pw_bytes = password.encode('utf-8')
                if not isinstance(stored, bytes):
                    stored = bytes(stored)

                match = bcrypt.checkpw(pw_bytes, stored)            
                if match:
                    # identification token to attach to user while logged in
                    token = secrets.token_urlsafe(32)
                    self.logged_in_accounts[token] = datetime.now()
                    return True, token
                else:
                    print("Password verification failed")
                    return False, None
                
            except Exception as e:
                print(f"Password verification error: {str(e)}")
                return False, None

        except Exception as e:
            print(f"Error occurred on login attempt: {e}")
            return False, None

    def is_valid_email(self, email: str) -> bool:
        """
        Determines that a provided email meets formatting requirements.
        - Param: email [str] -> User's email address.
        - Returns: True if the provided email is valid.
        """
        email_format = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_format, email))

    def is_valid_password(self, password: str) -> bool:
        """
        Determines that a provided password meets formatting and length requirements. Passwords must be
        at least 12 characters in length, and contain at least one upper-case, one lower-case, at least one
        special character, and at least one number.
        - Param: email [str] -> User's password.
        """
        if len(password) < 12:
            return False
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_number = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[-!@#$%^&*(),.?":{}|<>]', password))

        return has_lowercase and has_uppercase and has_number and has_special

    def user_mfa(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Sets up QR-based multifactor authentication for the user.
        - Param: email [str] -> User's email address.
        - Returns: True if multifactor authentication is set up, with a generated QR-code.
        """
        try:
            if not self.database.get_credentials(email):
                return False, None
            
            _, qr = self.mfa.generate_totp(email)
            if qr:
                return True, qr
            return False, None
        
        except Exception as e:
            print(f"Error occurred setting up multifactor authentication: {e}")
            return False, None

    def verify_authentication_code(self, email: str, code: str) -> Tuple[bool, str]:
        """
        Verifies an authentication code provided by the user.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> mfa-generated, user-provided authentication code.
        - Returns: True if authentication code is valid, with a message response based on its validity.
        """
        try:
            if not self.mfa.validate_code(email, code):
                return False, "Code Not Valid."
            return True, "Code Accepted."
        except Exception as e:
            return False, f"Error ocurred while verifying code: {str(e)}"

    def is_active(self, token: str) -> bool:
        """
        Checks if an account is currently logged in.
        - Param: token [str] -> Token identification assigned to an account at login.
        - Return: True if an account is currently logged in.
        """
        return token in self.logged_in_accounts
    
    def logout(self, token: str) -> bool:
        """
        Logs a user out of the application, which works by rendering the token provided at login void.
        - Param: token [str] -> identification token attached to a user upon successful login.
        - Returns: True if token is void.
        """
        if not token:
            return False

        if token in self.logged_in_accounts:
            del self.logged_in_accounts[token]
            return True
        return False

    

class AuthenticationDatabase:
    """
    Local database for user credentials.
    """

    def __init__(self):
        """
        Constructor for the Authentication database - setting up a path to its sqlite database.
        """
        self.path = "auth.db"
        self.create_auth_tables()

    def store_credentials(self, email: str, passwd: bytes) -> bool:
        """
        Stores user's credentials in the database, storing email identification and their password
        protected by the scrypt hashing function.
        - Param: email [str] -> User's email address.
        - Param: passwd [bytes] -> User's hashed password.
        - Returns: True if credentials are successfully stored in the database.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (email, passwd)
                    VALUES (?, ?)
                """, (email, passwd))
                conn.commit()
                result = cursor.rowcount > 0
                return result
        except sqlite3.Error as e:
            print(f"Error storing account credentials: {e}")
            return False

    def get_credentials(self, email: str) -> Optional[Tuple[str, bytes]]:
        """
        Fetches a user's credentials from the database.
        - Param: email [str] -> User's email address.
        - Returns: User's account credentials.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT email, passwd FROM users 
                    WHERE email = ?
                """, (email,))
                result =  cursor.fetchone()
                if result:
                    user_email, pw_bytes = result
                    if not isinstance(pw_bytes, bytes):
                        pw_bytes = bytes(pw_bytes)
                    return (user_email, pw_bytes)

                return None
        except sqlite3.Error as e:
            print(f"Error retrieving account credentials: {e}")
            return None

    def create_auth_tables(self):
        """
        Constructs database tables in the authentication database.
        """
        try:
            with sqlite3.connect(self.path) as conn:
                cursor = conn.cursor()
                cursor.execute("DROP TABLE IF EXISTS users")
                cursor.execute("""
                    CREATE TABLE users (
                        email TEXT PRIMARY KEY,
                        passwd BLOB NOT NULL
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(f"Error occurred while attempting to create sqlite database tables: {e}")
            raise
        