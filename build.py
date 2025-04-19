import subprocess
import sys
import os

# --- Configuration ---
SCRIPT_TO_COMPILE = "process_connection_monitor.py"
EXECUTABLE_NAME = "ProcessConMon"
ICON_FILE = None # Optional: specify path to a .ico file, e.g., "app.ico"
# --- End Configuration ---

def build():
    """Runs PyInstaller to build the executable."""
    print(f"Starting build process for {SCRIPT_TO_COMPILE}...")

    # Check if the target script exists
    if not os.path.exists(SCRIPT_TO_COMPILE):
        print(f"Error: Target script '{SCRIPT_TO_COMPILE}' not found.")
        sys.exit(1)

    # Construct the PyInstaller command
    command = [
        sys.executable,  # Use the current Python interpreter to run pyinstaller
        "-m", "PyInstaller",
        "--onefile",       # Bundle everything into a single executable
        "--windowed",      # Prevent console window from showing (for GUI apps)
        "--name", EXECUTABLE_NAME, # Set the name of the output executable
        "--clean",         # Clean PyInstaller cache and remove temporary files
        "--noconfirm",     # Overwrite output directory without asking
    ]

    # Add icon if specified
    if ICON_FILE and os.path.exists(ICON_FILE):
        command.extend(["--icon", ICON_FILE])
        print(f"Using icon: {ICON_FILE}")
    elif ICON_FILE:
        print(f"Warning: Icon file '{ICON_FILE}' not found. Building without icon.")

    # Add the target script
    command.append(SCRIPT_TO_COMPILE)

    print(f"Running command: {' '.join(command)}")

    try:
        # Run the command
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        print("-" * 30 + " Build Output " + "-" * 30)
        print(process.stdout)
        print("-" * 74)
        print(f"Build successful! Executable created at: dist\{EXECUTABLE_NAME}.exe")

    except subprocess.CalledProcessError as e:
        print("-" * 30 + " Build Error " + "-" * 30)
        print(f"Error during build process: {e}")
        print("----- STDOUT -----")
        print(e.stdout)
        print("----- STDERR -----")
        print(e.stderr)
        print("-" * 73)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: PyInstaller not found. Make sure it's installed (pip install pyinstaller)")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Ensure the script is running on Windows for .exe build
    if sys.platform != "win32":
        print("Warning: This build script is designed to create a Windows .exe file.")
        print("Running PyInstaller on a non-Windows OS may not produce the desired result")
        print("or might require additional setup (like Wine).")
        # Optional: Exit if not Windows, or just show warning and proceed
        # sys.exit(1)

    build() 