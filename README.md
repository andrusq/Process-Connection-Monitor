# Process Connection Monitor

````````````````````````````````````````````````````````````````````````````````````````````````````

 ______                                         ______ _______ _______      _______ _______ _______ 
|   __ \.----.-----.----.-----.-----.-----.    |      |       |    |  |    |   |   |       |    |  |
|    __/|   _|  _  |  __|  -__|__ --|__ --|    |   ---|   -   |       |    |       |   -   |       |
|___|   |__| |_____|____|_____|_____|_____|    |______|_______|__|____|    |__|_|__|_______|__|____|
                                                                                                    
                                                                         
````````````````````````````````````````````````````````````````````````````````````````````````````

A Python GUI application using Tkinter to monitor network connections for a specific process.

## Features

*   Lists processes with active network connections.
*   Monitors established connections for a selected process in real-time.
*   Displays remote IP address, port, GeoIP location (via ip-api.com), 
    and VirusTotal reputation (optional, requires API key).
*   Configurable scan interval.
*   Logs connection checks to `connection_monitor.log`.

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    ```
2.  Navigate to the project directory:
    ```bash
    cd <project-directory>
    ```
3.  (Optional but recommended) Create and activate a virtual environment:
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```
4.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running from Source

1.  Run the script:
    ```bash
    python process_connection_monitor.py
    ```
2.  Select a process from the dropdown list (refresh if needed).
3.  (Optional) Enable VirusTotal checks and enter your API key in the designated section.
4.  Click "Start Monitoring".

### Building the Executable (Windows)

1.  Ensure all dependencies are installed (including `pyinstaller`):
    ```bash
    pip install -r requirements.txt
    ```
2.  Run the build script:
    ```bash
    python build.py
    ```
3.  The executable (`ProcessConMon.exe`) will be located in the `dist` folder.

## Configuration

*   The VirusTotal API key is saved in `config.ini` when entered in the GUI.
*   Logs are saved to `connection_monitor.log`.

## Dependencies

*   Python 3.x
*   psutil
*   requests
*   pyinstaller (for building executable) 