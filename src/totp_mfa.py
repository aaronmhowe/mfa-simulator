class TOTPMFA:
    """
    Central class for the functional logic of the Time-Based One-Time Password
    Multifactor Authentication software, that sends a verification code to a user
    via email.
    """

    def __init__(self):
        """
        Constructor for the TOTPMFA class - constructing the length of the code, its timer
        to expiration (in seconds), and references to the EmailCode and DatabaseServer classes.
        """
        self.code_length = 6
        self.code_timer = 60
        self.email_code = EmailCode()
        self.database = DatabaseServer()

    def generate_code(self) -> str:
        """
        Generates a code for login verification.
        - Returns: The generated code.
        """
        pass

    def send_code(self, email: str) -> str:
        """
        Sends a generated verification code to a provided email address.
        - Param: email [str] -> User's email address.
        - Returns: The sent verification code.
        """
        pass

    def validate_code(self, email: str, code: str) -> bool:
        """
        Validates the code provided by the user.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Code provided by the user.
        - Returns: True if the code is valid
        """
        pass

    def store_mfa_code(self, email: str, code: str) -> None:
        """
        Stores the generated code.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Verification code to store.
        """
        pass

    def is_expired(self, time) -> bool:
        """
        Determines if a generated verification is expired or not.
        - Param: time -> the timestamp at which the code was generated.
        - Returns: True if the code is expired.
        """
        pass

    def clear_codes(self) -> None:
        """
        Deletes stored codes from the database when they're expired.
        """
        pass

class EmailCode:
    """
    Class for the functional logic of the email delivery method for one-time
    pass-code verification.
    """

    def __init__(self):
        """
        Constructor for the EmailCode class - initializes user credentials.
        """
        self.send_from: str = None
        self.password: str = None

    def send_to(self, email: str, code: str) -> bool:
        """
        Sends an email to a requesting user's email address containing the
        time-based one-time passcode for login verification.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Generated verification code.
        - Returns: True if the email was sent.
        """
        pass

    def message(self, email: str, code: str):
        """
        Constructs an automated message to accompany the verification in the
        verification email sent to the user.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Generated verification code.
        - Returns: MIMEMultipart message body and attached code.
        """
        pass

    def smtp_server(self):
        """
        Builds an SMTP server to handle transferring emails from server to server.
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
        self.path: str = "codes.db"

    def store_code(self, email: str, code: str, time) -> None:
        """
        Stores a generated verification code in the database.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Generated verification code.
        - Param: time -> Timestamp at which the verification code was generated.
        """
        pass

    def get_code(self, email: str) -> tuple:
        """
        Fetches a verification code for a user via their associated email address.
        - Param: email [str] -> User's email address.
        - Returns: A [Code, Time] pair.
        """
        pass

    def is_used(self, email: str, code: str) -> None:
        """
        Tags a code after its use as invalid to prevent possible fraudulent re-use.
        - Param: email [str] -> User's email address.
        - Param: code [str] -> Used verification code.
        """
        pass

    def delete_expired_codes(self) -> None:
        """
        Deletes expired codes from the database.
        """
        pass

    def create_tables(self) -> None:
        """
        Constructs database tables.
        """
        pass