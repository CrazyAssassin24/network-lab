import os
import getpass
from datetime import datetime


def run_command(command):

    command = command.strip()

    if command == "help":
        return """
Available commands:
help     - Show available commands
pwd      - Show current directory
ls       - List files and folders
date     - Show current date and time
whoami   - Show current username
exit     - Disconnect from server
"""

    elif command == "pwd":
        return os.getcwd()

    elif command == "ls":
        files = os.listdir(".")
        return "\n".join(files) if files else "Directory is empty"

    elif command == "date":
        return datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    elif command == "whoami":
        return getpass.getuser()

    else:
        return "Invalid command. Type 'help' to see available commands."
