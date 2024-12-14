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
        self.root.geometry("1280x920")
        win_width = self.root.winfo_screenwidth()
        win_height = self.root.winfo_screenheight()
        width = (win_width - 1280) // 2
        height = (win_height - 920) // 2
        self.root.geometry(f"1280x920+{width}+{height}")
        self.app = Application()
        self.frame = ttk.Frame(self.root)
        self.frame.pack(expand=True, fill='both', padx=20, pady=20)
        self.active_frame: Optional[ttk.Frame] = None
        self.display_startup()

    def close_active_frame(self):
        """
        Closes the active frame upon invokation.
        """
        if self.active_frame:
            self.active_frame.destroy()

    def display_startup(self):
        """
        Displays the startup view to the user with interactive components.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Multifactor Authentication Simulator", font=('Arial', 16))
        title.pack(pady=20)
        # initialize buttons for the user to either initiate login (transfer to login view) or registration (transfer to registratio view)
        ttk.Button(self.active_frame, text="Login", command=self.display_login).pack(pady=10)
        ttk.Button(self.active_frame, text="Register", command=self.display_registration).pack(pady=10)
        # third option to close application
        ttk.Button(self.active_frame, text="Exit", command=self.root.quit).pack(pady=10)


    def display_registration(self):
        """
        Displays the registration view to the user with interactive components.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Account Registration", font=('Arial', 16))
        title.pack(pady=20)
        # text box to enter email address
        ttk.Label(self.active_frame, text="Email Address: ").pack()
        email_input = tk.StringVar()
        email_box = ttk.Entry(self.active_frame, textvariable=email_input)
        email_box.pack()
        # text box to enter new password
        ttk.Label(self.active_frame, text="Create Password: ").pack()
        pass_input = tk.StringVar()
        pass_box = ttk.Entry(self.active_frame, textvariable=pass_input, show="*")
        pass_box.pack()
        # text box for password confirmation
        ttk.Label(self.active_frame, text="Re-Enter Password: ").pack()
        conf_input = tk.StringVar()
        conf_box = ttk.Entry(self.active_frame, textvariable=conf_input, show="*")
        conf_box.pack()

        def registration_manager():
            """
            Helper function for the registration view display.
            """
            email = email_input.get()
            password = pass_input.get()
            conf = conf_input.get()
            reg, response = self.app.app_registration(email, password, conf)
            if reg:
                messagebox.showinfo(VALIDITY_RESPONSE['REGISTRATION'], response)
                self.display_mfa_setup()
            else:
                messagebox.showerror(INVALIDITY_RESPONSE['REGISTRATION'], response)

                # button click to register account with entered credentials
        ttk.Button(self.active_frame, text="Register", command=registration_manager).pack(pady=20)
        ttk.Button(self.active_frame, text="Return to Startup", command=self.display_startup).pack()

    def display_login(self):
        """
        Displays the login view to the user with interactive components.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Login", font=("Arial", 16))
        title.pack(pady=20)
        ttk.Label(self.active_frame, text="Enter Email Address: ").pack()
        email_input = tk.StringVar()
        email_box = ttk.Entry(self.active_frame, textvariable=email_input)
        email_box.pack()
        ttk.Label(self.active_frame, text="Enter Password: ").pack()
        pass_input = tk.StringVar()
        pass_box = ttk.Entry(self.active_frame, textvariable=pass_input, show="*")
        pass_box.pack()

        def login_manager():
            """
            Helper function for the login view display.
            """
            email = email_input.get()
            password = pass_input.get()
            login, response = self.app.app_login(email, password)
            if login:
                messagebox.showinfo(VALIDITY_RESPONSE['LOGIN'], response)
                self.display_mfa_setup()
            else:
                messagebox.showerror(INVALIDITY_RESPONSE['LOGIN'], response)

        ttk.Button(self.active_frame, text="Login", command=login_manager).pack(pady=20)
        ttk.Button(self.active_frame, text="Return to Startup", command=self.display_startup).pack(pady=20)

    def display_mfa_setup(self):
        """
        Displays the multifactor authentication setup view to the user.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Multifactor Authentication Setup", font=("Arial", 16))
        title.pack(pady=20)
        setup, qr, _ = self.app.app_user_mfa()
        if setup and qr:
            # generate QR code
            qr_code = base64.b64decode(qr)
            qr_image = Image.open(io.BytesIO(qr_code))
            qr_generated = ImageTk.PhotoImage(qr_image)
            qr_frame = ttk.Frame(self.active_frame)
            qr_frame.pack(pady=10)
            # display QR code to user
            qr_display = ttk.Label(qr_frame, image=qr_generated)
            qr_display.image = qr_generated
            qr_display.pack(pady=20)
            ttk.Label(self.active_frame, text="Use Google Authenticator to Scan the QR Code").pack()

            secret_frame = ttk.Frame(self.active_frame)
            secret_frame.pack(pady=20)
            secret_key = self.app.auth.mfa.database.get_secret(self.app.get_user())
            secret_box = ttk.Entry(secret_frame, width=40)
            secret_box.insert(0, secret_key)
            secret_box.configure(state='readonly')
            secret_box.pack(pady=5)

            # button click proceeds to verification stage of mfa
            ttk.Button(self.active_frame, text="Advance to Verification", command=self.display_mfa_verification).pack(pady=10)
            ttk.Button(self.active_frame, text="Return to Startup", command=self.display_startup).pack(pady=10)
        else:
            ttk.Label(self.active_frame, text="QR Code Generation Failed").pack()
            ttk.Button(self.active_frame, text="Reset", command=self.display_registration).pack(pady=10)

    def display_mfa_verification(self):
        """
        Displays the multifactor authentication verification view to the user.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Multifactor Authentication Verification", font=("Arial", 16))
        title.pack(pady=20)
        ttk.Label(self.active_frame, text="Enter Verification Code Generated from Google Authenticator").pack()
        code_input = tk.StringVar()
        code_box = ttk.Entry(self.active_frame, textvariable=code_input)
        code_box.pack()

        def mfa_manager():
            """
            Helper function for the mfa setup/verification display.
            """
            code = code_input.get()
            verify, response = self.app.app_validate_code(code)
            if verify:
                messagebox.showinfo(VALIDITY_RESPONSE['CODE'], response)
                self.display_main()
            else:
                messagebox.showerror(INVALIDITY_RESPONSE['CODE'], response)

        ttk.Button(self.active_frame, text="Verify", command=mfa_manager).pack(pady=10)
        ttk.Button(self.active_frame, text="Return to Multifactor Authentication Setup", command=self.display_mfa_setup).pack(pady=10)

    def display_main(self):
        """
        Displays the home page view to the user.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="Home Page", font=("Arial", 16))
        title.pack(pady=20)
        ttk.Button(self.active_frame, text="View Profile", command=self.display_profile).pack(pady=10)
        ttk.Button(self.active_frame, text="Logout", command=self.ui_logout).pack(pady=10)

    def display_profile(self):
        """
        Displays the user-profile view to the user.
        """
        self.close_active_frame()
        self.active_frame = ttk.Frame(self.frame)
        self.active_frame.pack(expand=True)
        title = ttk.Label(self.active_frame, text="User Profile", font=("arial", 16))
        title.pack(pady=20)
        # displays the user's email address
        ttk.Label(self.active_frame, text=f"User: {self.app.get_user()}").pack(pady=10)
        ttk.Button(self.active_frame, text="Return to Home Page", command=self.display_main).pack(pady=10)

    def ui_logout(self):
        """
        Displays and manages the logout logic.
        """
        logout, response = self.app.app_logout()
        if logout:
            messagebox.showinfo(VALIDITY_RESPONSE['LOGOUT'], response)
            self.display_startup()
        else:
            messagebox.showerror(INVALIDITY_RESPONSE['LOGOUT'], response)

    def run(self):
        """
        Starts the thread for application loop.
        """
        self.root.mainloop()