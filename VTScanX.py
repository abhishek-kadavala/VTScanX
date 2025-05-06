import os
import hashlib
import argparse
import json
from datetime import datetime
import requests
from prettytable import PrettyTable
from colored import fg, attr
from tqdm import tqdm
import time
import getpass
import sys

# Server API endpoints
BASE_URL = "http://12.10.10.135:8000/"
SERVER_API_URL = f"{BASE_URL}/check_hash"
CACHE_FILE = "cache.json"
API_KEY=""

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
        return None

def get_all_files(path, include_subdirs=False):
    """Get all files in a folder"""
    file_paths = []
    if include_subdirs:
        for root, _, files in os.walk(path):
            for file in files:
                file_paths.append(os.path.join(root, file))
    else:
        for file in os.listdir(path):
            full_path = os.path.join(path, file)
            if os.path.isfile(full_path):
                file_paths.append(full_path)
    return file_paths

def load_cache():
    """Load cache data from cache.json"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def save_cache(cache):
    """Save updated cache to cache.json"""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)

def print_formatted_result(result):
    """Print a single result in a formatted table with color-coded scores"""
    table = PrettyTable()
    table.field_names = ["File", "SHA256", "Score", "Threat Category", "Threat Label", "Threat Name", "Message"]

    color_map = {
        range(0, 11): fg("green"),
        range(11, 51): fg("yellow"),
        range(51, 101): fg("red")
    }

    score = result.get("score")
    if score is not None and isinstance(score, int):
        for score_range, color in color_map.items():
            if score in score_range:
                score_color = color
                break
        else:
            score_color = fg("white")
        score_str = f"{score_color}{score}{attr('reset')}"
    else:
        score_str = "N/A"

    table.add_row([
        result.get("file", "unknown"),
        result.get("sha256", "unknown"),
        score_str,
        result.get("threat_category", "N/A"),
        result.get("threat_label", "N/A"),
        result.get("threat_name", "N/A"),
        result.get("message", "N/A")
    ])
    print(table)

def send_hash_to_server(file_data, verbose_mode=False):
    """Send hash data to the server and return response"""
    responses = []
    for file in file_data:
        try:
            headers = {
                "Authorization": f"Bearer {API_KEY}" 
            }
            response = requests.post(
                SERVER_API_URL,
                json={"hash_value": file['sha256']},
                headers=headers
            )
            if response.status_code == 200:
                res_data = response.json()
                res_data["file"] = file.get("file", "unknown")
                res_data["sha256"] = res_data.get("hash_value", "unknown")
                responses.append(res_data)
                if verbose_mode:
                    print(f"File: {res_data['file']} | SHA256: {res_data['sha256']} | Score: {res_data.get('score', 'N/A')}" + "".join([f" | {label}: {res_data[label]}" for label in ['threat_category', 'threat_label', 'threat_name'] if res_data.get(label)]) + f" | Message: {res_data.get('message', 'N/A')}")
            elif response.status_code == 429:
                # Stop further requests if the server returns 429 status code
                print(f"[!] Server responded with {response.status_code}: {response.json()['detail']}")
                sys.exit()
            else:
                error_response = {
                    "file": file.get('file', 'unknown'),
                    "sha256": file.get('sha256', 'unknown'),
                    "score": None,
                    "threat_category": "N/A",
                    "threat_label": "N/A",
                    "threat_name": "N/A",
                    "message": f"Server responded with {response.status_code}"
                }
                responses.append(error_response)
                if verbose_mode:
                    print(f"File: {error_response['file']} | SHA256: {error_response['sha256']} | Score: N/A | Message: {error_response['message']}")
        except Exception as e:
            error_response = {
                "file": file.get('file', 'unknown'),
                "sha256": file.get('sha256', 'unknown'),
                "score": None,
                "threat_category": "N/A",
                "threat_label": "N/A",
                "threat_name": "N/A",
                "message": str(e)
            }
            responses.append(error_response)
            if verbose_mode:
                print(f"File: {error_response['file']} | SHA256: {error_response['sha256']} | Score: N/A | Message: {error_response['message']}")
    return responses

def generate_report(server_response, output_path=None):
    """Generate report based on API response"""
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "results": server_response
    }

    if output_path:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[+] Report saved to {output_path}")
    else:
        print(json.dumps(report, indent=4))

def print_formatted_results(results):
    """Print results in a formatted table with color-coded scores"""
    table = PrettyTable()
    table.field_names = ["File", "SHA256", "Score", "Threat Category", "Threat Label", "Threat Name", "Message"]

    color_map = {
        range(0, 11): fg("green"),
        range(11, 51): fg("yellow"),
        range(51, 101): fg("red")
    }

    for result in results:
        score = result.get("score")
        if score is not None and isinstance(score, int):
            for score_range, color in color_map.items():
                if score in score_range:
                    score_color = color
                    break
            else:
                score_color = fg("white")
            score_str = f"{score_color}{score}{attr('reset')}"
        else:
            score_str = "N/A"

        table.add_row([
            result.get("file", "unknown"),
            result.get("sha256", "unknown"),
            score_str,
            result.get("threat_category", "N/A"),
            result.get("threat_label", "N/A"),
            result.get("threat_name", "N/A"),
            result.get("message", "N/A")
        ])

    print(table)

def show_loading(message, duration=2):
    for _ in tqdm(range(duration), desc=message):
        time.sleep(1)

def registration():
    print("\n--- User Registration ---")
    email = input("Enter your email: ")

    # Step 1: Request OTP
    print("\nRequesting OTP...")
    show_loading("Sending OTP", 2)
    response = requests.post(f"{BASE_URL}/request-otp", json={"email": email})
    if response.status_code != 200:
        print("Error requesting OTP:", response.json())
        return

    print("OTP sent to your email.")
    otp = input("Enter the OTP you received: ")
    api_key = input("Enter your VirusTotal API key: ")

    # Step 2: Verify OTP
    print("\nVerifying OTP...")
    show_loading("Verifying OTP", 2)
    response = requests.post(f"{BASE_URL}/verify-otp", json={
        "email": email,
        "otp": otp,
        "api_key": api_key
    })
    if response.status_code != 200:
        print("Error verifying OTP:", response.json())
        return

    print("OTP verified. Proceeding with registration...")

    # Step 3: Complete Registration
    while True:
        password = getpass.getpass("Enter your password: ").strip()
        con_password = getpass.getpass("Re-enter your password: ").strip()
        if password != con_password:
            print("Passwords do not match. Please try again.")
        elif not password.strip():
            print("Password cannot be empty. Please try again.")
        elif len(password) < 6:
            print("Password must be at least 6 characters long. Please try again.")
        else:
            break

    show_loading("Completing Registration", 2)
    response = requests.post(f"{BASE_URL}/complete-registration", json={
        "email": email,
        "password": password
    })
    if response.status_code == 200:
        data = response.json()
        print("\nRegistration successful!")
        print("Your user API key is:", data["api_key"])
    else:
        print("Error completing registration:", response.json())

def forgot_password(email_from_arg=None):
    print("\n--- Forgot Password ---")
    email = email_from_arg.strip() if email_from_arg else input("Enter your registered email: ").strip()

    # Step 1: Request OTP
    print("\nRequesting OTP...")
    show_loading("Sending OTP", 2)
    response = requests.post(f"{BASE_URL}/forgot-password", json={"email": email})
    if response.status_code != 200:
        print("Error requesting OTP:", response.json().get("detail", "Unknown error"))
        return

    print("OTP sent to your email.")

    # Step 2: Verify OTP
    otp = input("Enter the OTP you received: ").strip()
    print("\nVerifying OTP...")
    show_loading("Verifying OTP", 2)
    response = requests.post(f"{BASE_URL}/verify-resetpass-otp", json={"email": email, "otp": otp})
    if response.status_code != 200:
        print("Error verifying OTP:", response.json().get("detail", "Invalid OTP or expired."))
        return

    print("OTP verified successfully.")

    # Step 3: Enter and Confirm New Password
    while True:
        password = getpass.getpass("Enter your new password: ").strip()
        con_password = getpass.getpass("Re-enter your new password: ").strip()
        if not password:
            print("Password cannot be empty. Please try again.")
        elif password != con_password:
            print("Passwords do not match. Please try again.")
        else:
            break

    print("\nResetting password...")
    show_loading("Updating password", 2)
    response = requests.post(f"{BASE_URL}/reset-password", json={
        "email": email,
        "password": password
    })
    if response.status_code == 200:
        print("\n[✓] Password reset successfully! You can now log in with your new password.")
    else:
        print("Error resetting password:", response.json().get("detail", "Failed to reset password."))

def login():
    print("\n--- User Login ---")
    email = input("Enter your email: ").strip()
    password = getpass.getpass("Enter your password: ").strip()

    if not email or not password:
        print("Email and password are required.")
        return

    print("\nLogging in...")
    show_loading("Authenticating", 2)

    response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })

    if response.status_code == 200:
        data = response.json()
        print("\nLogin successful!")
        print("Your API Key:", data["api_key"])
        global API_KEY
        API_KEY = data["api_key"]  # Store for later use in session
    else:
        print("Login failed:", response.json().get("detail", "Invalid credentials."))

def main():
    parser = argparse.ArgumentParser(description="🔍 VirusTotal Hash Scanner Client with Caching")
    parser.add_argument("-f","--file",nargs="+",help="Single or multiple file paths to scan. Use spaces or comma-separated values (e.g., file1.exe file2.pdf or file1.exe,file2.pdf)")
    parser.add_argument("-p", "--path", help="Directory path to scan all files inside")
    parser.add_argument("-s", "--subdir", action="store_true", help="Include subdirectories")
    parser.add_argument("-r", "--report", action="store_true", help="Save the scan report to the default file (scan_report.json)")
    parser.add_argument("-o", "--output", help="Path to save the report JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-i", "--ignore-cache", action="store_true", help="Ignore cache and fetch updated data from the server")
    parser.add_argument("--reset", nargs="?", const=True, metavar="EMAIL", help="Reset password for the given email (sends OTP and prompts for new password)")
    parser.add_argument("--login", action="store_true", help="Login with email and password to get your API key")
    parser.add_argument("--register", action="store_true", help="Register a new account and get your API key")

    args = parser.parse_args()

    #Handle password reset first
    if args.reset is not None:
        if args.reset is True:  # No email provided
            email_input = input("Enter your registered email: ").strip()
            forgot_password(email_input)
        else:
            forgot_password(args.reset)
        return  # Stop further execution after reset

    #Handle registration
    if args.register:
        registration()
        return

    #Handle login
    if args.login:
        if API_KEY:
            print("Already logged in.")
        else:
            login()
        return

    #Check login/registration requirement
    if not API_KEY:
        print("No API key found. Please register or login first.")
        return

    if not args.file and not args.path:
        parser.error("one of the arguments -f/--file -p/--path is required")

    files_to_scan = []
    results = []
    cache = load_cache()

    # Process single file
    if args.file:
        file_inputs = []
        for entry in args.file:
            # Split by comma if user used comma-separated files
            if ',' in entry:
                file_inputs.extend(entry.split(','))
            else:
                file_inputs.append(entry)

        # Strip spaces and check if file exists
        for file_path in file_inputs:
            file_path = file_path.strip()
            if not os.path.isfile(file_path):
                print(f"[!] File not found: {file_path}")
                continue
            hash_val = calculate_sha256(file_path)
            if hash_val:
                files_to_scan.append({"file": file_path, "sha256": hash_val})

    # Process all files in folder
    elif args.path:
        if not os.path.isdir(args.path):
            print(f"[!] Invalid folder path: {args.path}")
            return
        all_files = get_all_files(args.path, include_subdirs=args.subdir)
        for file in all_files:
            hash_val = calculate_sha256(file)
            if hash_val:
                files_to_scan.append({"file": file, "sha256": hash_val})

    if not files_to_scan:
        print("[!] No valid files to scan.")
        return

    to_send = []
    for item in files_to_scan:
        hash_val = item["sha256"]
        if hash_val in cache and cache[hash_val] is not None and not args.ignore_cache:
            print(f"[~] Using cached result for {item['file']}")
            results.append({
                "file": item["file"],
                "sha256": hash_val,
                "score": cache[hash_val]["score"],
                "threat_category": cache[hash_val]["threat_category"],
                "threat_label": cache[hash_val]["threat_label"],
                "threat_name": cache[hash_val]["threat_name"],
                "message": "Cached result"
            })
        else:
            to_send.append(item)

    if to_send:
        print(f"[~] Sending {len(to_send)} new hashes to server...")
        server_response = send_hash_to_server(to_send, verbose_mode=args.verbose)
        for res in server_response:
            if "hash_value" in res:
                res["sha256"] = res.get("hash_value", "unknown")
                results.append(res)
                if res.get("score") is not None:
                    cache[res["sha256"]] = {
                        "score": res["score"],
                        "threat_category": res.get("threat_category", ""),
                        "threat_label": res.get("threat_label", ""),
                        "threat_name": res.get("threat_name", "")
                    }
            else:
                res["file"] = res.get("file", "unknown")
                res["sha256"] = res.get("sha256", "unknown")
                results.append(res)

    save_cache(cache)

    print_formatted_results(results)

    if args.report or args.output:
        report_path = args.output if args.output else "scan_report.json"
        generate_report(results, output_path=report_path)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting...")
