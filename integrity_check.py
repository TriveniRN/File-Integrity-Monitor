import json
import hashlib
import os
from datetime import datetime

# --------------------------------
# 1. Load the baseline
# --------------------------------

baseline_file = "baseline/baseline.json"

with open(baseline_file, "r") as file:
    baseline = json.load(file)

print("Baseline loaded successfully!")
print("Files in baseline:", len(baseline))
print()

# --------------------------------
# 2. Folder and log settings
# --------------------------------

protected_folder = "protected_files"
log_file = "logs/integrity_log.txt"

os.makedirs("logs", exist_ok=True)

# --------------------------------
# 3. Counters
# --------------------------------

unchanged_count = 0
modified_count = 0
new_count = 0
deleted_count = 0

# --------------------------------
# 4. Function to write logs
# --------------------------------

def write_log(message):

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a") as file:
        file.write(f"[{current_time}] {message}\n")

# --------------------------------
# 5. Check current files
# --------------------------------

for filename in os.listdir(protected_folder):

    file_path = os.path.join(protected_folder, filename)

    if os.path.isfile(file_path):

        # Calculate current SHA-256
        with open(file_path, "rb") as file:
            file_data = file.read()

        current_hash = hashlib.sha256(file_data).hexdigest()

        print("File:", filename)
        print("Current SHA-256:", current_hash)

        # Check if file existed in baseline
        if filename in baseline:

            # Compare with baseline
            if current_hash == baseline[filename]:

                print("Status: No change")
                unchanged_count += 1

            else:

                print("Status: FILE MODIFIED")
                modified_count += 1

                write_log(f"MODIFIED: {filename}")

        else:

            print("Status: NEW FILE")
            new_count += 1

            write_log(f"NEW FILE: {filename}")

        print()

# --------------------------------
# 6. Check for deleted files
# --------------------------------

print("Checking for deleted files...")

for filename in baseline:

    file_path = os.path.join(protected_folder, filename)

    if not os.path.exists(file_path):

        print("Status: FILE DELETED")
        print("File:", filename)

        deleted_count += 1

        write_log(f"DELETED: {filename}")

# --------------------------------
# 7. Integrity Check Summary
# --------------------------------

total_files = unchanged_count + modified_count + new_count

total_alerts = modified_count + new_count + deleted_count

print()
print("========================================")
print("       INTEGRITY CHECK SUMMARY")
print("========================================")
print()
print("Files currently present :", total_files)
print("No change              :", unchanged_count)
print("Modified               :", modified_count)
print("New files              :", new_count)
print("Deleted files          :", deleted_count)
print("Security alerts        :", total_alerts)
print()
print("========================================")
print("Integrity check completed.")
print("Log file:", log_file)
print("========================================")