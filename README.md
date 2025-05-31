# VTScanX

VTScanX is a free tool that allows users to scan multiple files at once on VirusTotal. It helps bypass the API key limitations, making bulk scanning fast and easy. With a clean interface, this tool is perfect for security researchers and malware analysts looking for a simple way to get VirusTotal results quickly.

---

## Features
- **Bulk Scanning**: Effortlessly scan multiple files and directories.
- **VirusTotal Integration**: Fetch scan results for files based on SHA256 hash values.
- **Caching**: Avoid redundant API calls by storing results in a local cache.
- **User Authentication**: Register, log in, and manage your account with ease.
- **Customizable Reports**: Generate detailed reports in JSON format.

---

## Linux Global Installation (Recommended)

1. **Get the bash install script**
   ```bash
   wget https://raw.githubusercontent.com/abhishek-kadavala/VTScanX/main/install-vtscanx-linux.sh
   ```

2. **Make the script executable**
   ```bash
   chmod +x install-vtscanx-linux.sh
   ```

3. **Run the script**
   ```bash
   ./install-vtscanx-linux.sh
   ```

---

This will automatically:
- Copy the VTScanX script to `/usr/local/bin/` as `vtscanx`
- Add the necessary shebang if missing
- Make it available as a command (`vtscanx`) anywhere in your terminal

**Now you can use VTScanX globally:**
```bash
vtscanx --register
vtscanx -f file1.exe
```
**Don’t forget to register yourself first!**

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/abhishek-kadavala/VTScanX.git
   cd VTScanX
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
2. Register and get your API key:
   ```bash
   python3 VTScanX.py --register
   ```
   Follow the registration process as prompted.
   Once completed, you will receive an API key that starts with vtscax_.

---
  ### Important:
  Open the source code and locate the API_KEY variable (which is blank by default).
  Set its value to the API key you received:
  ```bash
  API_KEY = "your_vtscanx_api_key_here"
  ```
   
---

## Usage

### Command-Line Arguments
VTScanX provides a variety of options to customize your scanning experience.

| Argument               | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| `-f`, `--file`         | Single or multiple file paths to scan (e.g., `file1.exe file2.pdf` or `file1.exe,file2.pdf`). |
| `-p`, `--path`         | Directory path to scan all files inside.                                                      |
| `-s`, `--subdir`       | Include subdirectories when scanning.                                                         |
| `-r`, `--report`       | Save the scan report to the default file (`scan_report.json`).                                |
| `-o`, `--output`       | Specify a custom path to save the report JSON file.                                           |
| `-v`, `--verbose`      | Enable verbose mode to display additional details.                                            |
| `-i`, `--ignore-cache` | Ignore cache and fetch updated data from the server.                                          |
| `--reset`              | Reset password for the given email (sends OTP and prompts for new password).                  |
| `--login`              | Log in with email and password to get your API key.                                           |
| `--register`           | Register a new account and get your API key.                                                  |

---

### Examples

#### 1. Scan a Single File
```bash
python3 VTScanX.py -f file1.exe
```

#### 2. Scan Multiple Files
```bash
python3 VTScanX.py -f file1.exe,file2.pdf
```

#### 3. Scan a Directory
```bash
python3 VTScanX.py -p /path/to/directory
```

#### 4. Scan a Directory and SubDirectory
```bash
python3 VTScanX.py -p /path/to/directory -s
```

#### 5. Enable Verbose Mode
```bash
python3 VTScanX.py -f file1.exe -v
```

#### 6. Generate a Report
```bash
python3 VTScanX.py -f file1.exe -r
```

---

## How It Works

1. **Hash Calculation**:
   - The tool calculates the SHA256 hash of the provided files using the `calculate_sha256` function.

2. **Caching**:
   - Results are stored in a local `cache.json` file to reduce redundant API calls.

3. **Server Communication**:
   - Hashes are sent to the server.
   - The server validates the API key and processes the hashes.

4. **Error Handling**:
   - If the API key is invalid, the server responds with a 429 status code, and the client stops further requests.

5. **Reporting**:
   - Results are printed in a formatted table and optionally saved as a JSON report.

---

## Authentication

### Registration
1. Run the following command:
   ```bash
   python3 VTScanX.py --register
   ```
2. Enter your email and follow the prompts to complete registration.

### Login
1. Run the following command:
   ```bash
   python3 VTScanX.py --login
   ```
2. Enter your email and password to retrieve your API key.

### Reset Password
1. Run the following command:
   ```bash
   python3 VTScanX.py --reset
   ```
2. Enter your email and reset the password
3. Alternatively, you can provide the email directly:
   ```bash
   python3 VTScanX.py --reset email_id
   ```

---

## Benefits
- **Efficient Bulk Scanning**: Save time by scanning multiple files simultaneously.
- **Custom Reports**: Get detailed insights into the scan results for analysis.
- **User-Friendly**: Simplified interface for both beginners and advanced users.
- **Flexible Options**: Customize your scans with various command-line arguments.

---

## Limitations
- **API Key Dependency**: Requires a valid VirusTotal API key for operation.

---

## Contributing
If you find any bugs or issues, please email the owners instead of contributing directly.
---

## License
This project is licensed. See the `LICENSE` file for details.

---

## Contact
For any queries or support, please contact the owner:
- **Name**: Abhishek Kadavala
- **GitHub**: [abhishek-kadavala](https://github.com/abhishek-kadavala)
- **mail**: abhishekkadavala11@gmail.com
- **LinkedIn**: [Abhishek Kadavala](https://www.linkedin.com/in/abhishek-kadavala-%F0%9F%87%AE%F0%9F%87%B3-95513a253/)
