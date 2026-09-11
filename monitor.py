import os
import time
import json
import hashlib
from datetime import datetime

# --------------------------------
# Settings
# --------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

protected_folder = os.path.join(BASE_DIR, "protected_files")
baseline_file = os.path.join(BASE_DIR, "baseline", "baseline.json")
log_file = os.path.join(BASE_DIR, "logs", "integrity_log.txt")
report_folder = os.path.join(BASE_DIR, "reports")

CHECK_INTERVAL = 5


# --------------------------------
# Create required folders
# --------------------------------

os.makedirs(os.path.dirname(log_file), exist_ok=True)
os.makedirs(report_folder, exist_ok=True)


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

def write_log(level, message):

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(log_file, "a") as file:
        file.write(
            f"[{current_time}] [{level}] {message}\n"
        )


# --------------------------------
# Function: Get current file hashes
# --------------------------------

def get_current_files():

    current_files = {}

    if not os.path.exists(protected_folder):
        print("ERROR: protected_files folder not found.")
        return current_files

    for filename in os.listdir(protected_folder):

        file_path = os.path.join(
            protected_folder,
            filename
        )

        if os.path.isfile(file_path):

            try:

                current_hash = calculate_hash(file_path)

                current_files[filename] = current_hash

            except (PermissionError, OSError):

                print(
                    f"WARNING: Unable to access {filename}"
                )

                write_log(
                    "WARNING",
                    f"Unable to access file: {filename}"
                )

    return current_files


# --------------------------------
# Function: Display statistics
# --------------------------------

def display_statistics():

    print()
    print("----------------------------------------")
    print("       SECURITY EVENT SUMMARY")
    print("----------------------------------------")
    print(f"New files       : {new_files_count}")
    print(f"Modified files  : {modified_files_count}")
    print(f"Deleted files   : {deleted_files_count}")
    print(f"Total alerts    : {total_alerts}")
    print("----------------------------------------")
    print()


# --------------------------------
# Function: Generate security report
# --------------------------------

def generate_report(start_time, stop_time):

    report_filename = (
        "security_report_"
        + start_time.replace(":", "-").replace(" ", "_")
        + ".txt"
    )

    report_file = os.path.join(
        report_folder,
        report_filename
    )

    with open(report_file, "w") as file:

        file.write("========================================\n")
        file.write("       SECURITY EVENT REPORT\n")
        file.write("========================================\n\n")

        file.write("Monitoring Session\n")
        file.write("------------------\n")
        file.write(f"Started : {start_time}\n")
        file.write(f"Stopped : {stop_time}\n\n")

        file.write("Event Summary\n")
        file.write("-------------\n")
        file.write(f"New files       : {new_files_count}\n")
        file.write(f"Modified files  : {modified_files_count}\n")
        file.write(f"Deleted files   : {deleted_files_count}\n")
        file.write(f"Total alerts    : {total_alerts}\n\n")

        file.write("Event History\n")
        file.write("-------------\n")

        if event_history:

            for event in event_history:

                file.write(
                    f"[{event['time']}] "
                    f"{event['type']:<10} : "
                    f"{event['file']}\n"
                )

                # --------------------------------
                # Hash information
                # --------------------------------

                if event["type"] == "MODIFIED":

                    file.write(
                        f"    Previous SHA-256 : "
                        f"{event['previous_hash']}\n"
                    )

                    file.write(
                        f"    Current SHA-256  : "
                        f"{event['current_hash']}\n"
                    )

                elif event["type"] == "NEW FILE":

                    file.write(
                        f"    Current SHA-256  : "
                        f"{event['current_hash']}\n"
                    )

                elif event["type"] == "DELETED":

                    file.write(
                        f"    Baseline SHA-256 : "
                        f"{event['baseline_hash']}\n"
                    )

                file.write("\n")

        else:

            file.write(
                "No security events detected.\n"
            )

        file.write(
            "========================================\n"
        )

        file.write(
            "       END OF SECURITY REPORT\n"
        )

        file.write(
            "========================================\n"
        )

    return report_filename


# --------------------------------
# Initial file state
# --------------------------------

previous_state = get_current_files()


# --------------------------------
# Security event counters
# --------------------------------

new_files_count = 0
modified_files_count = 0
deleted_files_count = 0
total_alerts = 0


# --------------------------------
# Event history
# --------------------------------

event_history = []


# --------------------------------
# Session start time
# --------------------------------

session_start = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)


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


write_log(
    "INFO",
    "Monitoring started"
)


# --------------------------------
# Continuous monitoring
# --------------------------------

try:

    while True:

        current_state = get_current_files()

        event_detected = False


        # --------------------------------
        # Check for NEW files
        # --------------------------------

        for filename in current_state:

            if filename not in previous_state:

                event_time = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                current_hash = current_state[filename]

                print(
                    f"[ALERT] NEW FILE: {filename}"
                )

                print(
                    f"Current SHA-256: {current_hash}"
                )

                write_log(
                    "ALERT",
                    f"NEW FILE: {filename} | "
                    f"SHA-256: {current_hash}"
                )

                event_history.append({
                    "time": event_time,
                    "type": "NEW FILE",
                    "file": filename,
                    "current_hash": current_hash
                })

                new_files_count += 1
                total_alerts += 1
                event_detected = True


        # --------------------------------
        # Check for MODIFIED files
        # --------------------------------

        for filename in current_state:

            if filename in previous_state:

                previous_hash = previous_state[filename]
                current_hash = current_state[filename]

                if current_hash != previous_hash:

                    event_time = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    print(
                        f"[ALERT] FILE MODIFIED: {filename}"
                    )

                    print(
                        f"Previous SHA-256: {previous_hash}"
                    )

                    print(
                        f"Current SHA-256 : {current_hash}"
                    )

                    write_log(
                        "ALERT",
                        f"MODIFIED: {filename} | "
                        f"Previous SHA-256: {previous_hash} | "
                        f"Current SHA-256: {current_hash}"
                    )

                    event_history.append({
                        "time": event_time,
                        "type": "MODIFIED",
                        "file": filename,
                        "previous_hash": previous_hash,
                        "current_hash": current_hash
                    })

                    modified_files_count += 1
                    total_alerts += 1
                    event_detected = True


        # --------------------------------
        # Check for DELETED files
        # --------------------------------

        for filename in previous_state:

            if filename not in current_state:

                event_time = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                baseline_hash = baseline.get(
                    filename,
                    previous_state[filename]
                )

                print(
                    f"[ALERT] FILE DELETED: {filename}"
                )

                print(
                    f"Baseline SHA-256: {baseline_hash}"
                )

                write_log(
                    "ALERT",
                    f"DELETED: {filename} | "
                    f"Baseline SHA-256: {baseline_hash}"
                )

                event_history.append({
                    "time": event_time,
                    "type": "DELETED",
                    "file": filename,
                    "baseline_hash": baseline_hash
                })

                deleted_files_count += 1
                total_alerts += 1
                event_detected = True


        # --------------------------------
        # Display statistics
        # --------------------------------

        if event_detected:

            display_statistics()


        # --------------------------------
        # Update state
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

    session_stop = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    write_log(
        "INFO",
        "Monitoring stopped"
    )

    report_filename = generate_report(
        session_start,
        session_stop
    )


    # --------------------------------
    # Final security summary
    # --------------------------------

    print()
    print("========================================")
    print("       FINAL SECURITY SUMMARY")
    print("========================================")

    print(
        f"New files       : {new_files_count}"
    )

    print(
        f"Modified files  : {modified_files_count}"
    )

    print(
        f"Deleted files   : {deleted_files_count}"
    )

    print(
        f"Total alerts    : {total_alerts}"
    )

    print()
    print("Security report generated:")
    print(
        f"reports/{report_filename}"
    )

    print()
    print("Monitoring stopped.")