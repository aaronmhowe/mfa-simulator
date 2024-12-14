import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional
from PIL import Image, ImageTk
import base64
import io
from .application import Application, ApplicationViews
from .constants import VALIDITY_RESPONSE, INVALIDITY_RESPONSE

class UI:
    """
    Implements the logic for the application's graphical user-interface.
    """

    def __init__(self):
        """
        Constructor for the UI class - initializes the window.
        """
        self.root = tk.Tk()
        self.root.title("MFA Simulator")
        self.root.geometry("1280x720")
        win_width = self.root.winfo_screenwidth()
        win_height = self.root.winfo_screenheight()
        width = (win_width - 1280) // 2
        height = (win_height - 720) // 2
        self.root.geometry(f"1280x720+{x}+{y}")
        self.app = Application()
        self.frame = ttk.Frame(self.root)
        self.frame.pack(expand=True, fill='both', padx=20, pady=20)
        self.active_frame = Optional[ttk.Frame] = None
        self.display_startup()

    def close_active_frame(self):
        """
        Closes the active frame upon invokation.
        """
        pass

    def display_startup(self):
        """
        Displays the startup view to the user.
        """
        pass

    def display_registration(self):
        """
        Displays the registration view to the user.
        """
        pass

    def registration_manager(self):
        """
        Helper function for the reigstration view display.
        """
        pass

    def display_login(self):
        """
        Displays the login view to the user.
        """
        pass

    def login_manager(self):
        """
        Helper function for the login view display.
        """
        pass

    def display_mfa_setup(self):
        """
        Displays the multifactor authentication setup view to the user.
        """
        pass

    def display_mfa_verification(self):
        """
        Displays the multifactor authentication verification view to the user.
        """
        pass

    def mfa_manager(self):
        """
        Helper function for the mfa setup/verification dispay.
        """
        pass

    def display_main(self):
        """
        Displays the home page view to the user.
        """
        pass

    def display_profile(self):
        """
        Displays the user-profile view to the user.
        """
        pass

    def ui_logout(self):
        """
        Displays and manages the logout logic.
        """
        pass

    def run(self):
        """
        Starts the thread for application loop.
        """
        self.root.mainloop()