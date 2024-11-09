import pyotp
from typing import Tuple
import sqlite3
from datetime import datetime
from typing import Optional, Tuple
import qrcode
import io
import base64


class TOTPMFA:
    """
    Central class for the functional logic of the Time-Based One-Time Password
    Multifactor Authentication software, that generates a QR verification code for a user.
    """

    def __init__(self):
        """
        Constructor for the TOTPMFA class - initializes the database.
        """

        self.database = DatabaseServer()


    def generate_totp(self, email: str) -> Tuple[str, str]:
        """
        Generates a secret key and uses it to construct a time-based one-time password
        as a QR Code.
        - Returns: the generated secret key and QR code
        """
        pass

    
    def validate_code(self, email: str, code: str) -> bool:
        """
        Validates the generated code.
        """
        pass


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
        """
        pass

    def get_secret(self, email: str) -> Optional[str]:
        """
        Fetches the secret key for a user via their associated email address.
        - Param: email [str] -> User's email address.
        - Returns: The secret key if it exists.
        """
        pass


    def delete_secret(self, email: str) -> bool:
        """
        Deletes a user's secret key.
        - Param: email [str] -> The user's email address.
        - Returns: True if the key is successfully deleted.
        """
        pass


    def create_tables(self) -> None:
        """
        Constructs database tables.
        """
        pass