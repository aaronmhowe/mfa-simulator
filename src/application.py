import getpass
from typing import Optional, Tuple, Dict, Any
from enum import Enum, auto
from .authentication import Authentication
from .totp_mfa import TOTPMFA
from .constants import VALIDITY_RESPONSE, INVALIDITY_RESPONSE, VIEWS

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

    def view_titles(self) -> str:
        """
        Constructs a dictionary containing the display titles of each view in the application.
        - Returns: The title of a view.
        """
        view_dict = {
            self.startup_view: VIEWS['STARTUP'],
            self.registration_view: VIEWS['REGISTRATION'],
            self.login_view: VIEWS['LOGIN'],
            self.mfa_setup_view: VIEWS['MFA_SETUP'],
            self.mfa_verification_view: VIEWS['MFA_VERIFICATION'],
            self.main_view: VIEWS['MAIN'],
            self.logout_view: VIEWS['LOGOUT']
        }
        return view_dict.get(self, VIEWS['STARTUP'])

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
        self.view = view

    def get_view(self) -> ApplicationViews:
        """
        Fetches the current view state of the application.
        - Returns: Current application view.
        """
        return self.view
    
    def get_title(self) -> str:
        """
        Fetches the title of the current view state of the application.
        - Returns: The title of the current view state.
        """
        return self.view.view_titles()
    
    def get_user(self) -> Optional[str]:
        """
        Fetches the account of a user currently logged into the application.
        - Returns: Identity of currently logged-in user.
        """
        return self.user
    
    def app_registration(self, email: str, password: str, password_confirmation: str) -> Tuple[bool, str]:
        """
        Follows state changes to registration and produces reponse messages.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's proposed password.
        - Param: confirmation [str] -> User's password confirmation.
        - Returns: True if user entries are valid with a text response from the application.
        """
        # display response to user if password confirmation doesn't match original
        if password != password_confirmation:
            return False, INVALIDITY_RESPONSE['PASSWORD_MISMATCH']
        if self.auth.register_account(email, password):
            self.user = email
            # generates a token after account registration, since account auto-logs in after registering
            _, self.token = self.auth.login(email, password)
            # transition to multifactor authentication setup view upon successful registration
            self.set_view(ApplicationViews.mfa_setup_view)
            return True, VALIDITY_RESPONSE['REGISTRATION']
        
        return False, "Registration Failed - See Email and Password Response."

    def app_login(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Follows state changes to login and produces response messages.
        - Param: email [str] -> User's email address.
        - Param: password [str] -> User's password.
        - Returns: True if user entries are valid with a text response from the application.
        """
        login, token = self.auth.login(email, password)
        if login and token:
            self.user = email
            self.token = token
            # transition to mfa code verification view upon successful login.
            self.set_view(ApplicationViews.mfa_verification_view)
            return True, VALIDITY_RESPONSE['LOGIN']
        
        return False, "Email/Password Not Recognized or Invalid."

    def app_validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Follows state changes to authentication email verification and produces response messages.
        - Param: email [str] -> User's email address.
        - Returns: True if email entry is valid with a text response from the application.
        """
        if self.auth.is_valid_email(email):
            return True, VALIDITY_RESPONSE['EMAIL']
        return False, INVALIDITY_RESPONSE['EMAIL']

    def app_validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Follows state changes to authentication password verification and produces response messages.
        - Param: password [str] -> User's password.
        - Returns: True if password entry is valid with a text response from the application.
        """
        if self.auth.is_valid_password(password):
            return True, VALIDITY_RESPONSE['PASSWORD']
        return False, INVALIDITY_RESPONSE['PASSWORD']

    def app_user_mfa(self) -> Tuple[bool, Optional[str], str]:
        """
        Follows state changes to multifactor authentication setup and produces response messages.
        - Returns: True if user entries are valid and server response is successful with a text response
        from the application.
        """
        if not self.user:
            return False, None, INVALIDITY_RESPONSE['USER_MISSING']
        mfa, qr = self.auth.user_mfa(self.user)
        if mfa and qr:
            return True, qr, VALIDITY_RESPONSE['MFA_SETUP']
        return False, None, INVALIDITY_RESPONSE['MFA_SETUP']

    def app_validate_code(self, code: str) -> Tuple[bool, str]:
        """
        Follows state changes to multifactor authentication code verification and produces response messages.
        - Param: code [str] ->  Code provided by the user.
        - Returns: True if user entries are valid with a text response from the application.
        """
        if not self.user:
            return False, INVALIDITY_RESPONSE['USER_MISSING']
        code, message = self.auth.verify_authentication_code(self.user, code)
        if code:
            self.set_view(ApplicationViews.main_view)
            return True, VALIDITY_RESPONSE['CODE']

        self.set_view(ApplicationViews.mfa_verification_view)
        return False, message
    
    def app_logout(self) -> Tuple[bool, str]:
        """
        Follows state changes to the logout procedure and produces a response message.
        - Returns: True if account logout is successful with a text response from the application.
        """
        if self.token and self.auth.logout(self.token):
            self.user = None
            self.token = None
            self.set_view(ApplicationViews.login_view)
            return True, VALIDITY_RESPONSE['LOGOUT']
        
        return False, INVALIDITY_RESPONSE['LOGOUT']

    def is_logged_in(self) -> bool:
        """
        Determines whether or not a user account is currently logged in based on the state of their login token.
        - Returns: True if there is a user and they have an active token.
        """
        return (self.view == ApplicationViews.main_view and self.user is not None and self.token is not None)
