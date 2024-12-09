import sqlite3
from typing import Optional, Tuple, Dict
from datetime import datetime, timedelta
import secrets
import bcrypt
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
        self.logged_in_accounts = Dict[str, datetime] = {}

    def register_account(self, email: str, password: str) -> bool:
        """
        Registers an account based on user-provided email and password credentials.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True if successfully registered.
        """
        pass

    def login(self, email: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Logs a user into the application by evaluating the user's login credentials,
        and attaches a session token to the user upon successful authentication that serves 
        as an identity.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True upon successful authentication, with a session token.
        """
        pass

    def is_valid_email(self, email: str) -> bool:
        """
        Determines that a provided email meets formatting requirements.
        - Param: email [str] -> User's email address.
        - Returns: True if the provided email is valid.
        """
        pass

    def is_valid_password(self, password: str) -> bool:
        """
        Determines that a provided password meets formatting and length requirements. Passwords must be
        at least 12 characters in length, and contain at least one upper-case, one lower-case, at least one
        special character, and at least one number.
        - Param: email [str] -> User's password.
        """
        pass

    def user_mfa(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Sets up QR-based multifactor authentication for the user.
        - Param: email [str] -> User's email address.
        - Returns: True if multifactor authentication is set up, with a generated QR-code.
        """
        pass

    def verify_authentication_code(self, email: str, code: str) -> Tuple[bool, str]:
        """
        Verifies an authentication code provided by the user.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> mfa-generated, user-provided authentication code.
        - Returns: True if authentication code is valid, with a message response based on its validity.
        """
        pass

    def logout(self, token: str) -> bool:
        """
        Logs a user out of the application, which works by rendering the token provided at login void.
        - Param: token [str] -> identification token attached to a user upon successful login.
        - Returns: True if token is void.
        """
        pass
    

class AuthenticationDatabase:
    """
    Local database for user credentials.
    """

    def __init__(self):
        """
        Constructor for the Authentication database - setting up a path to its sqlite database.
        """
        self.path = "auth.db"

    def store_credentials(self, email: str, passwd: bytes) -> bool:
        """
        Stores user's credentials in the database, storing email identification and their password
        protected by the scrypt hashing function.
        - Param: email [str] -> User's email address.
        - Param: passwd [bytes] -> User's hashed password.
        - Returns: True if credentials are successfully stored in the database.
        """
        pass

    def get_credentials(self, email: str) -> Optional[Tuple[str, bytes]]:
        """
        Fetches a user's credentials from the database.
        - Param: email [str] -> User's email address.
        - Returns: User's account credentials.
        """
        pass

    def create_auth_tables(self):
        """
        Constructs database tables in the authentication database.
        """
        pass
        