import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ui import UI

def main():
    """
    Entry point for the application - executes the main application loop with an instance
    of the application user-interface.
    """
    app = UI()
    app.run()

if __name__ == "__main__":
    main()