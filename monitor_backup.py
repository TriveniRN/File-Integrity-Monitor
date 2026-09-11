import os
import time
import json
import hashlib
from datetime import datetime

# --------------------------------
# Settings
# --------------------------------

protected_folder = "protected_files"
baseline_file = "baseline/baseline.json"
log_file = "logs/integrity_log.txt"

CHECK_INTERVAL = 5  # seconds


# --------------------------------
# Load baseline
# --------------------------------

with open(baseline_file, "r") as file:
    baseline = json.load(file)


# --------------------------------
# Function: Calculate SHA-256
# --------------------------------

def calculate_hash(file_path):

    with open(file_path, "rb") as file:
        file_data = file.read()

    return hashlib.sha256(file_data).hexdigest()


# --------------------------------
# Function: Write log
# --------------------------------

def write_log(message):

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a") as file:
        file.write(f"[{current_time}] {message}\n")


# --------------------------------
# Function: Get current file hashes
# --------------------------------

def get_current_files():

    current_files = {}

    for filename in os.listdir(protected_folder):

        file_path = os.path.join(protected_folder, filename)

        if os.path.isfile(file_path):

            try:
                current_hash = calculate_hash(file_path)
                current_files[filename] = current_hash

            except (PermissionError, OSError):
                print(f"Unable to access: {filename}")

    return current_files


# --------------------------------
# Initial file state
# --------------------------------

previous_state = get_current_files()


# --------------------------------
# Start monitor
# --------------------------------

print("========================================")
print("       FILE INTEGRITY MONITOR")
print("========================================")
print()
print("Monitoring started...")
print("Press Ctrl+C to stop.")
print()


# --------------------------------
# Continuous monitoring
# --------------------------------

try:

    while True:

        current_state = get_current_files()

        # --------------------------------
        # Check for new files
        # --------------------------------

        for filename in current_state:

            if filename not in previous_state:

                print(f"NEW FILE: {filename}")
                write_log(f"NEW FILE: {filename}")


        # --------------------------------
        # Check for modified files
        # --------------------------------

        for filename in current_state:

            if filename in previous_state:

                if current_state[filename] != previous_state[filename]:

                    print(f"FILE MODIFIED: {filename}")
                    write_log(f"MODIFIED: {filename}")


        # --------------------------------
        # Check for deleted files
        # --------------------------------

        for filename in previous_state:

            if filename not in current_state:

                print(f"FILE DELETED: {filename}")
                write_log(f"DELETED: {filename}")


        # --------------------------------
        # Update previous state
        # --------------------------------

        previous_state = current_state

        # --------------------------------
        # Wait before next check
        # --------------------------------

        time.sleep(CHECK_INTERVAL)


# --------------------------------
# Clean shutdown
# --------------------------------

except KeyboardInterrupt:

    print()
    print("Monitoring stopped.")