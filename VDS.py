#libraries 
import os # operating system 
import tkinter as tk
from tkinter import filedialog
from urllib.parse import urlparse
import re
import hashlib
import time
from datetime import datetime

# --- Configuration ---
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".js", ".scr"}
SAFE_EXTENSION_SUFFIX = ".safe"
# Basic simulation data
KNOWN_MALICIOUS_DOMAINS = {"malicious-domain.com", "phishing-site.net"}
URL_MALWARE_SIGNATURES = [r"badkeyword", r"exploitpattern"]
# Simulated Malware Hash Database (SHA-256)
# In a real application, this would be loaded from an external, updatable source.
MALWARE_HASH_DATABASE = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Example: SHA-256 of an empty file
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", # Fictional malware hash 1
    "f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9"  # Fictional malware hash 2
}
HISTORY_FILE = "scan_history.log" # Define the history file name

# --- History Manager ---
class HistoryManager:
    def __init__(self, history_file=HISTORY_FILE):
        self.history_file = history_file
        self._ensure_history_file_exists()

    def _ensure_history_file_exists(self):
        # Ensures the history file exists, creating it if necessary.
        if not os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'w') as f:
                    f.write("# Scan History Log\n")
            except IOError as e:
                print(f"ERROR: Could not create history file {self.history_file}: {e}")

    def add_record(self, record_type, message, details=""):
        
        # Adds a new record to the history file.
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        log_entry = f"[{timestamp}] [{record_type.upper()}] {message}"
        if details:
            log_entry += f" - Details: {details}"
        try:
            with open(self.history_file, 'a') as f:
                f.write(log_entry + "\n")
        except IOError as e:
            print(f"ERROR: Could not write to history file {self.history_file}: {e}")

    def view_history(self):
        # Reads and prints the entire history from the file.
        try:
            with open(self.history_file, 'r') as f:
                history_content = f.read()
                if not history_content.strip():
                    print("\n--- Scan History ---\nNo history records found.\n--------------------")
                else:
                    print("\n--- Scan History ---")
                    print(history_content)
                    print("--------------------")
        except FileNotFoundError:
            print(f"History file '{self.history_file}' not found. No history to display.")
        except IOError as e:
            print(f"ERROR: Could not read history file {self.history_file}: {e}")

# --- Base Class ---
class Scanner:
    # Base class for different scanning modules.
    
    def __init__(self, history_manager):
        self.history_manager = history_manager
        self.root = None # For Tkinter root window

    def _initialize_tk(self):
        # Initializes a Tkinter root window if one doesn't exist."""
        if self.root is None or not tk.Toplevel.winfo_exists(self.root):
            try:
                self.root = tk.Tk()
                self.root.withdraw() # Hide the main window
                return True
            except tk.TclError as e:
                self.display_error(f"Failed to initialize GUI environment (Tkinter): {e}. File selection unavailable.")
                self.root = None
                return False
        return True

    def display_error(self, message, details=""):
        print(f"ERROR: {message}")
        self.history_manager.add_record("ERROR", message, details)

    def display_warning(self, message, details=""):
        print(f"WARNING: {message}")
        self.history_manager.add_record("WARNING", message, details)

    def display_info(self, message, details=""):
        print(f"INFO: {message}")
        self.history_manager.add_record("INFO", message, details)

# --- URL Scanning Module ---
class URLScanner(Scanner):
    # Handles scanning of URLs for malicious domains and patterns.
    def __init__(self, history_manager):
        super().__init__(history_manager)
        self.malicious_domains = KNOWN_MALICIOUS_DOMAINS
        self.malware_signatures = [re.compile(pattern, re.IGNORECASE) for pattern in URL_MALWARE_SIGNATURES]

    def scan(self, url):
        # Performs domain check and simulated signature scan on a URL.
        
        self.display_info(f"Scanning URL: {url}")
        threat_found = False
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            if not domain:
                self.display_error("Invalid URL format. Could not extract domain.", url)
                self.history_manager.add_record("URL_SCAN", f"Failed: Invalid URL format for {url}", "Invalid URL")
                return False

            # 1. Domain Check
            if domain in self.malicious_domains:
                self.display_warning(f"Malicious domain detected: {domain}", url)
                threat_found = True

            # 2. Malware Signature Check (Basic Simulation)
            for pattern in self.malware_signatures:
                if pattern.search(url):
                    self.display_warning(f"Potential malware signature pattern found in URL: {pattern.pattern}", url)
                    threat_found = True

            if threat_found:
                self.history_manager.add_record("URL_SCAN", f"Threat detected for {url}", "Malicious domain or signature found")
            else:
                self.display_info("URL appears to be safe based on basic checks.", url)
                self.history_manager.add_record("URL_SCAN", f"Clean: {url}", "No threats detected")
            return True

        except Exception as e:
            self.display_error(f"An unexpected error occurred during URL scanning: {e}", url)
            self.history_manager.add_record("URL_SCAN", f"Error during scan for {url}", str(e))
            return False

# --- File Scanning Module (Triggers Antivirus on Suspicious Extension) ---
class FileScanner(Scanner):
    # Handles file selection via Tkinter, checks extension, and triggers Antivirus if suspicious.
    def __init__(self, antivirus_instance, history_manager):
        super().__init__(history_manager)
        self.suspicious_extensions = SUSPICIOUS_EXTENSIONS
        self.antivirus = antivirus_instance

    def select_file(self):
        if not self._initialize_tk():
            return None
        try:
            file_path = filedialog.askopenfilename(title="Select a file to scan", parent=self.root)
            if file_path:
                return file_path
            else:
                self.display_info("File selection cancelled.")
                return None
        except Exception as e:
            self.display_error(f"An error occurred during file selection: {e}")
            return None
        finally:
            if self.root and tk.Toplevel.winfo_exists(self.root):
                 self.root.destroy()
                 self.root = None

    def scan(self, file_path):
        # """Checks the extension and triggers Antivirus scan if suspicious."""
        if not file_path:
            self.display_error("No file path provided for scanning.")
            self.history_manager.add_record("FILE_SCAN", "Failed: No file path provided", "N/A")
            return False

        self.display_info(f"Performing initial file scan: {file_path}")
        try:
            if not os.path.exists(file_path):
                self.display_error(f"File not found: {file_path}", file_path)
                self.history_manager.add_record("FILE_SCAN", f"Failed: File not found {file_path}", "File not found")
                return False
            if not os.path.isfile(file_path):
                 self.display_error(f"Path is not a file: {file_path}", file_path)
                 self.history_manager.add_record("FILE_SCAN", f"Failed: Path is not a file {file_path}", "Not a file")
                 return False

            _, extension = os.path.splitext(file_path)
            extension = extension.lower()

            if extension in self.suspicious_extensions:
                self.display_warning(f"!!! POTENTIAL THREAT DETECTED (Suspicious Extension) !!!", file_path)
                self.display_warning(f"The file '{os.path.basename(file_path)}' has a potentially dangerous extension: {extension}", file_path)
                self.display_warning("Proceeding to full Antivirus scan...", file_path)
                self.history_manager.add_record("FILE_SCAN", f"Suspicious extension: {file_path}", f"Extension: {extension}. Triggering AV scan.")
                return self.antivirus.scan_and_clean(file_path)
            else:
                self.display_info(f"File '{os.path.basename(file_path)}' does not have a known suspicious extension ({extension}). Basic scan complete.", file_path)
                self.history_manager.add_record("FILE_SCAN", f"Clean (basic): {file_path}", f"Extension: {extension}. No suspicious extension.")
                return True

        except Exception as e:
            self.display_error(f"An unexpected error occurred during file scanning: {e}", file_path)
            self.history_manager.add_record("FILE_SCAN", f"Error during scan for {file_path}", str(e))
            return False

    def scan_interactive(self):
        file_path = self.select_file()
        if file_path:
            self.scan(file_path)

# --- Antivirus Module (Enhanced) ---
class Antivirus(Scanner):
    # """Performs multiple checks (hash) and simulates cleaning/monitoring."""
    def __init__(self, history_manager):
        super().__init__(history_manager)
        self.suspicious_extensions = SUSPICIOUS_EXTENSIONS
        self.safe_suffix = SAFE_EXTENSION_SUFFIX
        self.malware_hashes = MALWARE_HASH_DATABASE

    def select_file(self):
        # """Opens a file dialog for the user to select a file for Antivirus scan."""
        if not self._initialize_tk():
            return None
        try:
            file_path = filedialog.askopenfilename(title="Select a file for Antivirus Scan", parent=self.root)
            if file_path:
                return file_path
            else:
                self.display_info("File selection cancelled.")
                return None
        except Exception as e:
            self.display_error(f"An error occurred during file selection: {e}")
            return None
        finally:
            if self.root and tk.Toplevel.winfo_exists(self.root):
                self.root.destroy()
                self.root = None

    def _calculate_sha256(self, file_path):
        """Calculates the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError as e:
            self.display_error(f"Could not read file {file_path} for hashing: {e}", file_path)
            return None
        except Exception as e:
            self.display_error(f"An error occurred during hashing: {e}", file_path)
            return None

    def _simulate_system_monitoring(self, file_path):
        """ Placeholder for system change monitoring. """
        self.display_info(f"Simulating system monitoring for changes caused by {os.path.basename(file_path)}...")
        time.sleep(0.5)
        self.display_info("System Monitoring Simulation: No unexpected system changes detected.")

    def scan_and_clean(self, file_path):
        # """Performs hash check, monitoring, and offers rename if extension is suspicious."""
        self.history_manager.add_record("AV_SCAN_START", f"Starting AV scan for {file_path}")
        if not file_path:
            self.display_error("No file path provided for Antivirus scan.")
            self.history_manager.add_record("AV_SCAN", "Failed: No file path provided", "N/A")
            return False

        self.display_info(f"--- Starting Full Antivirus Scan for: {file_path} ---")
        is_suspicious_ext = False
        is_known_malware_hash = False
        scan_result = "Clean"

        try:
            if not os.path.exists(file_path):
                self.display_error(f"File not found: {file_path}", file_path)
                self.history_manager.add_record("AV_SCAN", f"Failed: File not found {file_path}", "File not found")
                return False
            if not os.path.isfile(file_path):
                self.display_error(f"Path is not a file: {file_path}", file_path)
                self.history_manager.add_record("AV_SCAN", f"Failed: Path is not a file {file_path}", "Not a file")
                return False

            # 1. Check Extension (primarily for renaming logic now)
            _, extension = os.path.splitext(file_path)
            extension = extension.lower()
            if extension in self.suspicious_extensions:
                is_suspicious_ext = True
                self.display_warning(f"Extension Check: File has a suspicious extension: {extension}", file_path)
            else:
                self.display_info(f"Extension Check: File '{os.path.basename(file_path)}' extension ({extension}) is not in the suspicious list.", file_path)

            # 2. SHA-256 Hash Check
            file_hash = self._calculate_sha256(file_path)
            if file_hash:
                self.display_info(f"File SHA-256 Hash: {file_hash}", file_path)
                if file_hash in self.malware_hashes:
                    self.display_warning(f"!!! MALWARE DETECTED BY HASH !!!", file_path)
                    self.display_warning(f"Hash Check: File '{os.path.basename(file_path)}' matches a known malware signature.", file_path)
                    is_known_malware_hash = True
                    scan_result = "Malware Detected (Hash)"
                else:
                    self.display_info("Hash Check: File hash does not match known malware signatures.", file_path)
            else:
                self.display_warning("Hash Check: Could not calculate file hash.", file_path)
                scan_result = "Error (Hash Calc)"

            # 3. Simulated System Monitoring
            self._simulate_system_monitoring(file_path)

            # 4. Action: Rename only if extension is suspicious
            if is_suspicious_ext:
                self.display_warning(f"The file has a suspicious extension ('{extension}'). Renaming is recommended.", file_path)
                try:
                    rename_confirm = input(f"Do you want to rename '{os.path.basename(file_path)}' to '{os.path.basename(file_path)}{self.safe_suffix}'? (y/n): ").lower()
                    if rename_confirm == 'yes':
                        new_file_path = file_path + self.safe_suffix
                        try:
                            os.rename(file_path, new_file_path)
                            self.display_info(f"Successfully renamed file to: {new_file_path}", file_path)
                            self.display_info("Note: This only changes the name and does NOT remove actual malware.", file_path)
                            self.history_manager.add_record("AV_ACTION", f"Renamed {file_path} to {new_file_path}", "Renamed due to suspicious extension")
                            scan_result += " & Renamed"
                        except OSError as oe:
                            self.display_error(f"Failed to rename file: {oe}. Check permissions or if the file is in use.", file_path)
                            self.history_manager.add_record("AV_ACTION", f"Failed to rename {file_path}", str(oe))
                            scan_result += " & Rename Failed"
                            return False
                    else:
                        self.display_info("File not renamed.", file_path)
                        self.history_manager.add_record("AV_ACTION", f"Rename skipped for {file_path}", "User declined rename")
                except EOFError:
                    self.display_warning("Could not get user input for renaming (non-interactive environment?). Skipping rename action.", file_path)
                    self.history_manager.add_record("AV_ACTION", f"Rename skipped for {file_path}", "Non-interactive environment")

            elif is_known_malware_hash:
                self.display_warning(f"File '{os.path.basename(file_path)}' was flagged by hash check but has a non-suspicious extension. Renaming not offered. Manual review strongly recommended.", file_path)
            else:
                if not is_suspicious_ext:
                    self.display_info(f"File '{os.path.basename(file_path)}' passed Antivirus checks.", file_path)

            self.history_manager.add_record("AV_SCAN_END", f"AV scan finished for {file_path}", scan_result)
            return True
        except Exception as e:
            self.display_error(f"An unexpected error occurred during the antivirus scan: {e}", file_path)
            self.history_manager.add_record("AV_SCAN", f"Error during scan for {file_path}", str(e))
            return False

    def scan_interactive(self):
        file_path = self.select_file()
        if file_path:
            self.scan_and_clean(file_path)

class VirusDetectionSystemApp:
    def __init__(self):
        self.history_manager = HistoryManager()
        self.url_scanner = URLScanner(self.history_manager)
        self.antivirus = Antivirus(self.history_manager)
        self.file_scanner = FileScanner(antivirus_instance=self.antivirus, history_manager=self.history_manager)

    def display_menu(self):
        print("\n--- Virus Detection System Menu ---")
        print("1. Scan URL")
        print("2. Scan File (Extension Check -> Antivirus Scan if suspicious)")
        print("3. Antivirus Scan (Select File -> Hash, Monitor, Rename)")
        print("4. View Scan History")
        print("5. Exit")
        print("-----------------------------------")

    def run(self):
        while True:
            self.display_menu()
            try:
                choice = input("Enter your choice (1-5): ")
                if choice == '1':
                    url = input("Enter the URL to scan: ")
                    self.url_scanner.scan(url)
                elif choice == '2':
                    self.file_scanner.scan_interactive()
                elif choice == '3':
                    self.antivirus.scan_interactive()
                elif choice == '4':
                    self.history_manager.view_history()
                elif choice == '5':
                    print("Exiting Virus Detection System.")
                    break
                else:
                    print("Invalid choice. Please enter a number between 1 and 5.")
            except ValueError:
                 print("Invalid input. Please enter a number.")
            except EOFError:
                 print("\nInput stream closed. Exiting.")
                 break
            except Exception as e:
                 print(f"An unexpected error occurred in the main loop: {e}")

if __name__ == "__main__":
    app = VirusDetectionSystemApp()
    app.run()
