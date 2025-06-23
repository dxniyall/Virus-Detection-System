# 🛡️ Virus Detection System – Python-Based File & URL Scanner:

This project is a Python-based Virus Detection System that simulates basic antivirus and malware scanning techniques for both files and URLs. Designed with modularity and educational use in mind, it combines GUI-based file selection (via Tkinter), simulated domain/signature threat analysis, suspicious extension handling, and SHA-256 hash scanning.

Whether you're learning about cybersecurity fundamentals or building a foundation for your own antivirus tool, this project provides a robust starting point.

# Features

### ✅ URL Scanner

* Parses and checks URLs for:

  * **Known malicious domains**
  * **Regex-based malware signature patterns**
* Logs scan results with timestamps
* Alerts users to suspicious or malicious URLs

### 🗂️ File Scanner

* Uses a simple file dialog to select a file
* Checks file extension against a list of **suspicious types** (`.exe`, `.bat`, etc.)
* Triggers a full **Antivirus scan** if extension is flagged
* Logs all activity with detailed messages

### 🧪 Antivirus Module

* Calculates **SHA-256 hash** of selected file
* Compares file hash against a mock **malware signature database**
* Simulates **system change monitoring** after scan
* Offers **optional file renaming** if extension is risky
* Handles non-interactive environments gracefully

### 📝 Scan History

* All scan events, warnings, errors, and actions are logged in a file: `scan_history.log`
* Provides a user-friendly method to **view scan history**

---

## 💻 Technologies Used

* **Python 3.x**
* `tkinter` – for GUI file selection
* `hashlib` – for SHA-256 hashing
* `urllib.parse` – for domain extraction
* `re` – for regex pattern matching
* `datetime`, `time`, `os` – standard utilities for logging, scanning, and file handling

---

## 📂 Folder Structure

```
.
├── virus_detection_system.py       # Main application script
├── scan_history.log                # Auto-generated scan history file
├── README.md                       # Project overview and instructions
└── LICENSE                         # Licensing information (optional)
```

---

## 🚀 How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/virus-detection-system.git
   cd virus-detection-system
   ```

2. Run the script:

   ```bash
   python virus_detection_system.py
   ```

> Ensure Python and Tkinter are installed in your environment.

---

## ⚠️ Disclaimer

This is a **simulation tool** created for educational and demonstration purposes.
It **does not perform real-time or heuristic malware detection**, nor does it integrate with actual antivirus engines.
**Do not rely on it for actual threat prevention** on production systems.

---

## 🤝 Contributions

Contributions, suggestions, and improvements are welcome!
Feel free to fork the repository, submit issues, or create pull requests.

---

## 📜 License

This project is open-source and available under the **MIT License**.
