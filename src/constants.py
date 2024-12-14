"""
Constants to be used throughout application implementaion.
"""

DB_PATH = {
    'AUTH': 'db/auth.db',
    'MFA': 'db/secrets.db'
}

DB_TABLES = {
    'USERS': 'users',
    'TOTP_SECRETS': 'totp_secrets',
    'VERIFICATION_ATTEMPTS': 'verification_attempts'
}

AUTH_SETTINGS = {
    'MIN_PASSWORD_LENGTH': 12,
    'MAX_LOGIN_ATTEMPTS': 3,
    'LOGIN_TIMEOUT': 60,
    'TOKEN_SIZE': 32,
}

MFA_SETTINGS = {
    'CODE_LENGTH': 6,
    'VERIFICATION_WINDOW': 1,
    'QR_CODE_SIZE': 10,
    'QR_CODE_BORDER_SIZE': 4
}

VALIDITY_RESPONSE = {
    'REGISTRATION': "Registration Complete.",
    'LOGIN': "Successfully Logged into Application.",
    'LOGOUT': "Account Logged Out.",
    'EMAIL': "Email Accepted.",
    'PASSWORD': "Password Accepted.",
    'MFA_SETUP': "Multifactor Authentication Enabled.",
    'CODE': "Code Accepted."
}

INVALIDITY_RESPONSE = {
    'REGISTRATION': "Registration Failed - See Email and Password Response.",
    'LOGIN': "Email/Password Not Recognized or Invalid.",
    'LOGOUT': "Error occurred trying to logout!",
    'EMAIL': "Invalid Email Format!",
    'PASSWORD': "Invalid Password: Must be at least 12 characters in length, have at least one lowercase, one uppercase, one special character, and one number!",
    'PASSWORD_MISMATCH': "Password confirmation does not match!",
    'MFA_SETUP': "Multifactor Authentication setup failed!",
    'CODE': "Code Not Valid.",
    'USER_MISSING': "Missing User.",
    'DATABASE': "Database Error: {}",
    'TOKEN': "Invalid or Expired Token."
}

VIEWS = {
    'STARTUP': "MFA Simulator",
    'REGISTRATION': "Account Registration",
    'LOGIN': "Account Login",
    'MFA_SETUP': "Setup Multifactor Authentication",
    'MFA_VERIFICATION': "Code Verification",
    'MAIN': "Home Page",
    'LOGOUT': "Logging Out..."
}

EMAIL_CONFIG = {
    'SMTP_SERVER': 'smtp.gmail.com',
    'SMTP_PORT': 587,
    'SENDER': 'mfa.simulator@domain.com',
    'SUBJECT': 'MFA Simulator - Verification Code'
}