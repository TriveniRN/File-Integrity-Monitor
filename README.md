# File Integrity Monitor

A Python-based file integrity monitoring system that uses **SHA-256 hashing** to detect unauthorized or unexpected changes in protected files.

## Features

* Create a secure baseline of protected files using SHA-256 hashes
* Detect **new files**
* Detect **modified files**
* Detect **deleted files**
* Continuous file monitoring
* Graphical User Interface (GUI)
* Manual integrity checking through command line
* Security event logging
* Automatic security reports

## Project Structure

```text
File-Integrity-Monitor/
├── gui.py                # Main GUI application
├── integrity_check.py    # Manual integrity checker
├── monitor.py            # Continuous file monitor
├── README.md             # Project documentation
└── .gitignore            # Git ignore rules
```

## How It Works

1. The user places files inside the `protected_files` folder.
2. A baseline is created by calculating the **SHA-256 hash** of each file.
3. During an integrity check or continuous monitoring session, the current file hashes are compared with the baseline.
4. The system identifies:

   * **Modified** files when their hash changes
   * **New** files that were not present in the baseline
   * **Deleted** files that were present in the baseline but are no longer available
5. Detected events are recorded in logs and security reports.

## Technologies Used

* **Python**
* **SHA-256 Cryptographic Hashing**
* **Tkinter**
* **JSON**
* **File System Monitoring**

## Applications

This project demonstrates the basic principles of **file integrity monitoring** and can be used as a learning project for understanding file security, cryptographic hashing, and security event detection.

## Requirements

* Python 3.x
* Tkinter (usually included with standard Python installations)
* Windows operating system

No external Python packages are required.

## How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/TriveniRN/File-Integrity-Monitor.git
cd File-Integrity-Monitor
```

### 2. Create the Protected Files Folder

Create a folder named:

```text
protected_files
```

Place the files you want to monitor inside this folder.

### 3. Run the GUI

```bash
python gui.py
```

The GUI allows you to create a baseline, check file integrity, start or stop continuous monitoring, and view security reports.

### 4. Run the Manual Integrity Checker

```bash
python integrity_check.py
```

This performs a manual comparison between the current files and the stored baseline.

### 5. Run the Continuous Monitor

```bash
python monitor.py
```

The continuous monitor checks the protected files periodically and records detected security events.

