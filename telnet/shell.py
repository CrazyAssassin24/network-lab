import os
import sys
import platform
import getpass
import socket
import shutil
from datetime import datetime


# Track the current working directory for cd support
_cwd = os.getcwd()


def run_command(command):
    global _cwd

    command = command.strip()
    parts = command.split(maxsplit=1)
    cmd = parts[0] if parts else ""
    args = parts[1] if len(parts) > 1 else ""

    if cmd == "help":
        return """
Available commands:
  help              - Show available commands
  pwd               - Show current directory
  ls [path]         - List files and folders
  cd <path>         - Change current directory
  cat <file>        - Display file contents
  head <file>       - Show first 10 lines of a file
  tail <file>       - Show last 10 lines of a file
  touch <file>      - Create an empty file
  mkdir <name>      - Create a new directory
  rmdir <name>      - Remove an empty directory
  rm <file>         - Delete a file
  cp <src> <dst>    - Copy a file
  mv <src> <dst>    - Move / rename a file
  echo <text>       - Print text back
  date              - Show current date and time
  uptime            - Show system uptime (approx)
  whoami            - Show current username
  hostname          - Show machine hostname
  uname             - Show OS and platform info
  disk              - Show disk usage
  env               - Show environment variables
  clear             - Clear screen (client-side hint)
  exit              - Disconnect from server
"""

    # ---------- filesystem navigation ----------

    elif cmd == "pwd":
        return _cwd

    elif cmd == "ls":
        target = os.path.join(_cwd, args) if args else _cwd
        try:
            entries = os.listdir(target)
            if not entries:
                return "Directory is empty"
            result = []
            for entry in sorted(entries):
                full = os.path.join(target, entry)
                if os.path.isdir(full):
                    result.append(f"[DIR]  {entry}")
                else:
                    size = os.path.getsize(full)
                    result.append(f"       {entry}  ({size} bytes)")
            return "\n".join(result)
        except FileNotFoundError:
            return f"ls: '{target}' not found."
        except PermissionError:
            return f"ls: permission denied for '{target}'."

    elif cmd == "cd":
        if not args:
            return "Usage: cd <path>"
        target = os.path.join(_cwd, args)
        target = os.path.abspath(target)
        if os.path.isdir(target):
            _cwd = target
            return f"Changed directory to {_cwd}"
        else:
            return f"cd: '{args}' is not a directory."

    # ---------- file reading ----------

    elif cmd == "cat":
        if not args:
            return "Usage: cat <file>"
        filepath = os.path.join(_cwd, args)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return f"cat: '{args}' not found."
        except PermissionError:
            return f"cat: permission denied for '{args}'."

    elif cmd == "head":
        if not args:
            return "Usage: head <file>"
        filepath = os.path.join(_cwd, args)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= 10:
                        break
                    lines.append(line.rstrip("\n"))
                return "\n".join(lines)
        except FileNotFoundError:
            return f"head: '{args}' not found."
        except PermissionError:
            return f"head: permission denied for '{args}'."

    elif cmd == "tail":
        if not args:
            return "Usage: tail <file>"
        filepath = os.path.join(_cwd, args)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                last = lines[-10:] if len(lines) >= 10 else lines
                return "\n".join(l.rstrip("\n") for l in last)
        except FileNotFoundError:
            return f"tail: '{args}' not found."
        except PermissionError:
            return f"tail: permission denied for '{args}'."

    # ---------- file / directory manipulation ----------

    elif cmd == "touch":
        if not args:
            return "Usage: touch <file>"
        filepath = os.path.join(_cwd, args)
        try:
            with open(filepath, "a"):
                pass
            return f"Touched '{args}'."
        except PermissionError:
            return f"touch: permission denied for '{args}'."

    elif cmd == "mkdir":
        if not args:
            return "Usage: mkdir <name>"
        dirpath = os.path.join(_cwd, args)
        try:
            os.makedirs(dirpath, exist_ok=False)
            return f"Directory '{args}' created."
        except FileExistsError:
            return f"mkdir: '{args}' already exists."
        except PermissionError:
            return f"mkdir: permission denied."

    elif cmd == "rmdir":
        if not args:
            return "Usage: rmdir <name>"
        dirpath = os.path.join(_cwd, args)
        try:
            os.rmdir(dirpath)
            return f"Directory '{args}' removed."
        except FileNotFoundError:
            return f"rmdir: '{args}' not found."
        except OSError:
            return f"rmdir: '{args}' is not empty or not a directory."
        except PermissionError:
            return f"rmdir: permission denied."

    elif cmd == "rm":
        if not args:
            return "Usage: rm <file>"
        filepath = os.path.join(_cwd, args)
        try:
            os.remove(filepath)
            return f"File '{args}' deleted."
        except FileNotFoundError:
            return f"rm: '{args}' not found."
        except IsADirectoryError:
            return f"rm: '{args}' is a directory. Use rmdir."
        except PermissionError:
            return f"rm: permission denied for '{args}'."

    elif cmd == "cp":
        if not args or len(args.split()) < 2:
            return "Usage: cp <source> <destination>"
        src, dst = args.split(maxsplit=1)
        src_path = os.path.join(_cwd, src)
        dst_path = os.path.join(_cwd, dst)
        try:
            shutil.copy2(src_path, dst_path)
            return f"Copied '{src}' -> '{dst}'."
        except FileNotFoundError:
            return f"cp: '{src}' not found."
        except PermissionError:
            return f"cp: permission denied."

    elif cmd == "mv":
        if not args or len(args.split()) < 2:
            return "Usage: mv <source> <destination>"
        src, dst = args.split(maxsplit=1)
        src_path = os.path.join(_cwd, src)
        dst_path = os.path.join(_cwd, dst)
        try:
            shutil.move(src_path, dst_path)
            return f"Moved '{src}' -> '{dst}'."
        except FileNotFoundError:
            return f"mv: '{src}' not found."
        except PermissionError:
            return f"mv: permission denied."

    # ---------- output / info ----------

    elif cmd == "echo":
        return args

    elif cmd == "date":
        return datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    elif cmd == "uptime":
        try:
            if platform.system() == "Windows":
                import ctypes
                lib = ctypes.windll.kernel32
                tick = lib.GetTickCount64()
                seconds = tick // 1000
            else:
                with open("/proc/uptime", "r") as f:
                    seconds = int(float(f.readline().split()[0]))
            days, rem = divmod(seconds, 86400)
            hours, rem = divmod(rem, 3600)
            mins, secs = divmod(rem, 60)
            return f"Uptime: {days}d {hours}h {mins}m {secs}s"
        except Exception:
            return "uptime: could not determine system uptime."

    elif cmd == "whoami":
        return getpass.getuser()

    elif cmd == "hostname":
        return socket.gethostname()

    elif cmd == "uname":
        return (
            f"System  : {platform.system()}\n"
            f"Node    : {platform.node()}\n"
            f"Release : {platform.release()}\n"
            f"Version : {platform.version()}\n"
            f"Machine : {platform.machine()}\n"
            f"Python  : {sys.version}"
        )

    elif cmd == "disk":
        try:
            usage = shutil.disk_usage(_cwd)
            total_gb = usage.total / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            pct = (usage.used / usage.total) * 100
            return (
                f"Total : {total_gb:.2f} GB\n"
                f"Used  : {used_gb:.2f} GB ({pct:.1f}%)\n"
                f"Free  : {free_gb:.2f} GB"
            )
        except Exception:
            return "disk: could not determine disk usage."

    elif cmd == "env":
        lines = [f"{k}={v}" for k, v in sorted(os.environ.items())]
        return "\n".join(lines)

    elif cmd == "clear":
        return "__CLEAR__"

    else:
        return f"Unknown command: '{cmd}'. Type 'help' to see available commands."
