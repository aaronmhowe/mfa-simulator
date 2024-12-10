import getpass
from typing import Optional, Tuple, Dict, Any
from enum import Enum, auto
from .authentication import Authentication
from .totp_mfa import TOTPMFA

class ApplicationViews(Enum):
    """
    Initializes the views for state changes.
    """
    
    startup_view = auto()
    registration_view = auto()
    login_view = auto()
    mfa_setup_view = auto()
    mfa_verification_view = auto()
    main_view = auto()
    logout_view = auto()

class Application:
    """
    Handles changes to application state from user behavior.
    """

    def __init__(self):
        """
        Constructor for the Application class - initializes the state of the application.
        """
        self.auth = Authentication()
        self.view = ApplicationViews.startup_view
        self.user: Optional[str] = None
        self.token: Optional[str] = None

    def set_view(self, view: ApplicationViews) -> None:
        """
        Updates the application view from state changes based on user behavior.
        - Param: view [ApplicationViews] -> Current application view.
        """
        pass

    def get_view(self) -> ApplicationViews:
        """
        Fetches the current view state of the application.
        - Returns: Current application view.
        """
        return self.view
    
    def get_user(self) -> Optional[str]:
        """
        Fetches the account of a user currently logged into the application.
        - Returns: Identity of currently logged-in user.
        """
        return self.user
    
    def app_registration(self, email: str, password: str, confirmation: str) -> Tuple[bool, str]:
        """
        Follows state changes to registration and produces reponse messages.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's proposed password.
        - Param: confirmation [str] -> Application response.
        - Returns: True if user entries are valid with a text response from the application.
        """
        pass

    def app_login(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Follows state changes to login and produces response messages.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True if user entries are valid with a text response from the application.
        """
        pass

    def app_validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Follows state changes to authentication email verification and produces response messages.
        - Param: email [str] -> User's email address.
        - Returns: True if email entry is valid with a text response from the application.
        """
        pass

    def app_validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Follows state changes to authentication password verification and produces response messages.
        - Param: password [str] -> User's password.
        - Returns: True if password entry is valid with a text response from the application.
        """

    def app_user_mfa(self) -> Tuple[bool, Optional[str], str]:
        """
        Follows state changes to multifactor authentication setup and produces response messages.
        - Returns: True if user entries are valid and server response is successful with a text response
        from the application.
        """
        pass

    def app_validate_code(self, code: str) -> Tuple[bool, str]:
        """
        Follows state changes to multifactor authentication code verification and produces response messages.
        - Param: code [str] ->  Code provided by the user.
        - Returns: True if user entries are valid with a text response from the application.
        """
        pass

    def app_logout(self) -> Tuple[bool, str]:
        """
        Follows state changes to the logout procedure and produces a response message.
        - Returns: True if account logout is successful with a text response from the application.
        """
        pass

    def is_logged_in(self) -> bool:
        """
        Determines whether or not a user account is currently logged in based on the state of their login token.
        - Returns: True if there is a user and they have an active token.
        """
        pass
