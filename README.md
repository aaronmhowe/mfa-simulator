# Simulating a Multi-Factor Authentication Service
Simple UI-based application that simulates a login page that employs a multi-factor authentication service.

## Instructions for Running this Program
1. Install Python 3
    - This program's interpreter is Python 3+, I am using Python 3.10.12, you can download and install Python 3 from this [link](https://www.python.org/downloads/source/).
        - Note: That link takes you to the Python 3 release page for Linux/UNIX Operating Systems. I highly recommend this program is ran on such system.
2. Install PIP: PIP is required for this program.
    - Windows Installation Guide:
        1. On your system search, search for Windows Powershell, Git Bash, or CMD. Right-click the result and click 'Run as Administrator'
        2. type and enter this command:
            `curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py`
            PIP should download to your system.
        3. To install, enter this command:
            `python get-pip.py`
        4. Verify PIP installed by entering:
            `python -m pip help`
            Entering this command should display the location on your system of where PIP is installed
        5. Add a PATH variable for PIP
            1. Open the Windows Search, and type and enter "Environment Variables"
            2. System Properties should open, at the bottom of the window, click "Environment Variables".
            3. This will open a list of environment variables, double-click 'Path', or single-click and then click 'Edit'
            4. Click 'New', and then add the directory of where PIP is installed on your system. This directory should've been displayed from entering into your commmand prompt: `python -m pip help`
            5. Click 'OK' and the changes should save.
        6. Open a clean CMD, Bash, or Powershell, then type and enter `pip help`. This should display the same location information from step 4. You might have to instead enter `pip3 help`. If you're having issues, it might be wise to add the directory where your Python3 installation is located to the same PATH variables from step 5.
    - Linux/UNIX Installation Guide:
        1. In your system terminal, type `wget https://bootstrap.pypa.io/get-pip.py`
            This will download the installer.
        2. Install PIP to your system by typing and entering: `python3 ./get-pip.py`
            PIP should now be installed.
3. Install Pyotp, QRCode, Pillow, and BCrypt
    - Installation Guide:
        1. In your system terminal, enter this command:
            - pip install pyotp qrcode pillow bcrypt
### Unix/Linux Users Only
3. Configure the Shell Scripts.
    - The shell script `run_code.sh` is used to compile and run the application.
    - The shell script `rm_db.sh` is used to clear the authentication and secrets databases so a user may continuously test the registration flow with the same email.
    - `run_code.sh` and `rm_db.sh` will need a couple commands entered into the terminal before they will be executable.
        1. CD into `/mfa-simulator` (`cd path/to/file/mfa-simulator`)
        2. Type and enter `chmod +x run_code.sh` and `chmod +x rm_db.sh` and enter your password if/when prompted.
        3. `run_code.sh` and `rm_db.sh` should now be executable. Type and enter `./run_code.sh` to run the application, and `./rm_db.sh` to delete the credentials and stored secret for an account you wish to re-register with.

## Report
- The primary purpose of this application is to learn about multifactor authentication and how it is implemented as a solution to the problem of brute-force password cracking and dictionary attacks.
- An attacker can still use brute-force tactics to crack a user's password, but due to the added layer of account authentication, further tactics would need to be employed to gain access to a user's account.
- The most vulnerable points of attack with the MFA implemented in this application are SQL injections, phishing, social engineering, and man-in-the-middle.
- Verification code brute-force cracking is still possible, but at minimal risk because the verification codes change at the end of short time interval. 
- A more concerning brute-force attack an actor could make is cracking the secret key generated by the application that is used to generate a 6 digit verification code, but this would take a long time and use a lot of resources to achieve.

## Resources
### Python's One-Time Password Library
https://pyauth.github.io/pyotp/ 
### Python's Testing Framework unittest
https://docs.python.org/3/library/unittest.html
### Python's QR Code Documentation
https://pypi.org/project/qrcode/
### Informational Videos
- Multi-factor Authentication: Programming Using Python: https://www.youtube.com/watch?v=C-jkO6coJkk 

- How to Store Data with Python and SQLite3: https://www.youtube.com/watch?v=RZI-v-Z1W4c 

- Tkinter - Switch Frames: https://www.youtube.com/watch?v=4hamShRNxgg 
### SQLite Python
- Creating Tables: https://www.sqlitetutorial.net/sqlite-python/creating-tables/

- Building Password Databases: https://magepy.hashnode.dev/python-and-sqlite-building-password-databases 
### Python's BCrypt Password Hash Function
- BCrypt Documentation & Files: https://pypi.org/project/bcrypt/

- Hashing Passwords in Python with BCrypt: https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/ 
### Constants in Python
https://realpython.com/python-constants/ 
### Python Tkinter
https://www.geeksforgeeks.org/python-gui-tkinter/ 
### TOTP Token Generator
https://totp.danhersam.com/ 
