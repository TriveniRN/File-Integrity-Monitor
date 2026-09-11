import os
import json
import hashlib
import threading
import queue
from datetime import datetime
import tkinter as tk
from tkinter import messagebox


# ========================================
# PROJECT PATHS
# ========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROTECTED_FOLDER = os.path.join(
    BASE_DIR,
    "protected_files"
)

BASELINE_FOLDER = os.path.join(
    BASE_DIR,
    "baseline"
)

BASELINE_FILE = os.path.join(
    BASELINE_FOLDER,
    "baseline.json"
)

REPORTS_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)

LOGS_FOLDER = os.path.join(
    BASE_DIR,
    "logs"
)

LOG_FILE = os.path.join(
    LOGS_FOLDER,
    "integrity_log.txt"
)


# ========================================
# GLOBAL VARIABLES
# ========================================

baseline = {}

monitoring = False
monitor_thread = None

stop_event = threading.Event()

previous_state = {}

new_count = 0
modified_count = 0
deleted_count = 0

event_history = []

event_queue = queue.Queue()

session_start = None

baseline_created_time = None


# ========================================
# LOAD BASELINE
# ========================================

def load_baseline():

    global baseline
    global baseline_created_time

    baseline = {}
    baseline_created_time = None

    if not os.path.exists(BASELINE_FILE):
        return

    try:

        with open(
            BASELINE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        # --------------------------------
        # New baseline format
        # --------------------------------

        if "files" in data:

            baseline = data.get(
                "files",
                {}
            )

            baseline_created_time = data.get(
                "created",
                None
            )

        # --------------------------------
        # Old baseline format
        # --------------------------------

        else:

            baseline = data

            baseline_created_time = None

    except (
        json.JSONDecodeError,
        OSError
    ):

        baseline = {}
        baseline_created_time = None


load_baseline()


# ========================================
# SHA-256 FUNCTION
# ========================================

def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(
        file_path,
        "rb"
    ) as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ========================================
# GET CURRENT FILE STATE
# ========================================

def get_current_state():

    current_state = {}

    if not os.path.exists(
        PROTECTED_FOLDER
    ):

        return current_state

    for filename in os.listdir(
        PROTECTED_FOLDER
    ):

        file_path = os.path.join(
            PROTECTED_FOLDER,
            filename
        )

        if os.path.isfile(file_path):

            try:

                current_state[filename] = calculate_hash(
                    file_path
                )

            except (
                PermissionError,
                OSError
            ):

                pass

    return current_state


# ========================================
# WRITE SECURITY LOG
# ========================================

def write_log(event):

    os.makedirs(
        LOGS_FOLDER,
        exist_ok=True
    )

    try:

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                f"[{event['time']}] "
                f"{event['type']} : "
                f"{event['filename']}\n"
            )

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
                    f"    Previous SHA-256 : "
                    f"{event['previous_hash']}\n"
                )

            file.write("\n")

    except OSError:

        pass


# ========================================
# CREATE BASELINE
# ========================================

def create_baseline():

    global baseline
    global baseline_created_time

    if monitoring:

        messagebox.showwarning(
            "Monitoring Active",
            "Please stop monitoring before creating a new baseline."
        )

        return

    if not os.path.exists(
        PROTECTED_FOLDER
    ):

        messagebox.showerror(
            "Error",
            "Protected files folder was not found."
        )

        return

    current_state = get_current_state()

    if not current_state:

        messagebox.showwarning(
            "No Files",
            "No files were found in the protected_files folder."
        )

        return

    os.makedirs(
        BASELINE_FOLDER,
        exist_ok=True
    )

    creation_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    baseline_data = {

        "created": creation_time,

        "files": current_state

    }

    try:

        with open(
            BASELINE_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                baseline_data,
                file,
                indent=4
            )

        baseline = current_state

        baseline_created_time = creation_time

        update_status_information()

        messagebox.showinfo(
            "Baseline Created",
            "Baseline created successfully.\n\n"
            f"Protected files: {len(baseline)}\n\n"
            f"Created: {creation_time}"
        )

    except OSError as error:

        messagebox.showerror(
            "Error",
            f"Could not create baseline.\n\n{error}"
        )


# ========================================
# CHECK INTEGRITY
# ========================================

def check_integrity():

    if monitoring:

        messagebox.showwarning(
            "Monitoring Active",
            "Please stop monitoring before performing an integrity check."
        )

        return

    load_baseline()

    if not baseline:

        messagebox.showerror(
            "Baseline Not Found",
            "No valid baseline was found.\n\n"
            "Please create a baseline first."
        )

        update_status_information()

        return

    current_state = get_current_state()

    modified_files = []
    new_files = []
    deleted_files = []

    # --------------------------------
    # Check new and modified files
    # --------------------------------

    for filename, current_hash in current_state.items():

        if filename not in baseline:

            new_files.append(filename)

        elif current_hash != baseline[filename]:

            modified_files.append(filename)

    # --------------------------------
    # Check deleted files
    # --------------------------------

    for filename in baseline:

        if filename not in current_state:

            deleted_files.append(filename)

    total_changes = (
        len(modified_files)
        + len(new_files)
        + len(deleted_files)
    )

    # --------------------------------
    # Integrity passed
    # --------------------------------

    if total_changes == 0:

        messagebox.showinfo(
            "Integrity Check",
            "INTEGRITY CHECK PASSED\n\n"
            "No changes were detected.\n\n"
            f"Files checked: {len(baseline)}"
        )

        return

    # --------------------------------
    # Integrity violation
    # --------------------------------

    result = (
        "INTEGRITY VIOLATION DETECTED\n\n"
        f"Modified files : {len(modified_files)}\n"
        f"New files      : {len(new_files)}\n"
        f"Deleted files  : {len(deleted_files)}\n"
        f"Total changes  : {total_changes}\n"
    )

    if modified_files:

        result += "\nModified:\n"

        for filename in modified_files:

            result += (
                f"  - {filename}\n"
            )

    if new_files:

        result += "\nNew:\n"

        for filename in new_files:

            result += (
                f"  - {filename}\n"
            )

    if deleted_files:

        result += "\nDeleted:\n"

        for filename in deleted_files:

            result += (
                f"  - {filename}\n"
            )

    messagebox.showwarning(
        "Integrity Check",
        result
    )


# ========================================
# ADD SECURITY EVENT
# ========================================

def add_event(
    event_type,
    filename,
    previous_hash=None,
    current_hash=None
):

    global new_count
    global modified_count
    global deleted_count

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if event_type == "NEW FILE":

        new_count += 1

    elif event_type == "MODIFIED":

        modified_count += 1

    elif event_type == "DELETED":

        deleted_count += 1

    event = {

        "time": current_time,

        "type": event_type,

        "filename": filename,

        "previous_hash": previous_hash,

        "current_hash": current_hash

    }

    event_history.append(
        event
    )

    write_log(
        event
    )

    event_queue.put(
        event
    )


# ========================================
# MONITOR FUNCTION
# ========================================

def monitor_files():

    global previous_state

    while not stop_event.is_set():

        current_state = get_current_state()

        # --------------------------------
        # New and modified files
        # --------------------------------

        for filename, current_hash in current_state.items():

            if filename not in baseline:

                if filename not in previous_state:

                    add_event(
                        "NEW FILE",
                        filename,
                        current_hash=current_hash
                    )

            else:

                if filename in previous_state:

                    previous_hash = previous_state[
                        filename
                    ]

                    if current_hash != previous_hash:

                        add_event(
                            "MODIFIED",
                            filename,
                            previous_hash,
                            current_hash
                        )

                else:

                    if current_hash != baseline[filename]:

                        add_event(
                            "MODIFIED",
                            filename,
                            baseline[filename],
                            current_hash
                        )

        # --------------------------------
        # Deleted files
        # --------------------------------

        for filename in previous_state:

            if filename not in current_state:

                add_event(
                    "DELETED",
                    filename,
                    previous_state[filename]
                )

        previous_state = current_state

        stop_event.wait(1)


# ========================================
# PROCESS GUI EVENTS
# ========================================

def process_events():

    while not event_queue.empty():

        try:

            event = event_queue.get_nowait()

        except queue.Empty:

            break

        event_type = event["type"]
        filename = event["filename"]

        events_box.config(
            state=tk.NORMAL
        )

        # --------------------------------
        # Timestamp
        # --------------------------------

        events_box.insert(
            tk.END,
            f"[{event['time']}] "
            f"{event_type}: {filename}\n"
        )

        # --------------------------------
        # Hash information
        # --------------------------------

        if event_type == "NEW FILE":

            events_box.insert(
                tk.END,
                f"Current SHA-256: "
                f"{event['current_hash']}\n\n"
            )

        elif event_type == "MODIFIED":

            events_box.insert(
                tk.END,
                f"Previous SHA-256: "
                f"{event['previous_hash']}\n"
            )

            events_box.insert(
                tk.END,
                f"Current SHA-256 : "
                f"{event['current_hash']}\n\n"
            )

        elif event_type == "DELETED":

            events_box.insert(
                tk.END,
                f"Previous SHA-256: "
                f"{event['previous_hash']}\n\n"
            )

        events_box.see(
            tk.END
        )

        events_box.config(
            state=tk.DISABLED
        )

        update_counters()

    root.after(
        200,
        process_events
    )


# ========================================
# UPDATE COUNTERS
# ========================================

def update_counters():

    new_label.config(
        text=f"New Files\n{new_count}"
    )

    modified_label.config(
        text=f"Modified Files\n{modified_count}"
    )

    deleted_label.config(
        text=f"Deleted Files\n{deleted_count}"
    )

    alerts_label.config(
        text=(
            f"Security Alerts\n"
            f"{new_count + modified_count + deleted_count}"
        )
    )


# ========================================
# UPDATE STATUS INFORMATION
# ========================================

def update_status_information():

    protected_label.config(
        text=f"Protected Files\n{len(baseline)}"
    )

    if baseline:

        baseline_status_label.config(
            text=(
                "Baseline: CREATED\n"
                f"{baseline_created_time or 'Existing baseline'}"
            )
        )

    else:

        baseline_status_label.config(
            text="Baseline: NOT CREATED"
        )


# ========================================
# CLEAR EVENTS
# ========================================

def clear_events():

    events_box.config(
        state=tk.NORMAL
    )

    events_box.delete(
        "1.0",
        tk.END
    )

    events_box.insert(
        tk.END,
        "No security events detected.\n"
    )

    events_box.config(
        state=tk.DISABLED
    )


# ========================================
# START MONITOR
# ========================================

def start_monitor():

    global monitoring
    global monitor_thread
    global previous_state
    global new_count
    global modified_count
    global deleted_count
    global event_history
    global session_start

    if monitoring:
        return

    load_baseline()

    if not baseline:

        messagebox.showwarning(
            "Baseline Required",
            "No baseline is loaded.\n\n"
            "Please create a baseline first."
        )

        return

    if not os.path.exists(
        PROTECTED_FOLDER
    ):

        messagebox.showerror(
            "Error",
            "Protected files folder was not found."
        )

        return

    new_count = 0
    modified_count = 0
    deleted_count = 0

    event_history = []

    update_counters()

    previous_state = get_current_state()

    stop_event.clear()

    monitoring = True

    session_start = datetime.now()

    status_label.config(
        text="MONITORING ACTIVE"
    )

    start_button.config(
        state=tk.DISABLED
    )

    stop_button.config(
        state=tk.NORMAL
    )

    create_baseline_button.config(
        state=tk.DISABLED
    )

    check_integrity_button.config(
        state=tk.DISABLED
    )

    clear_events_button.config(
        state=tk.DISABLED
    )

    events_box.config(
        state=tk.NORMAL
    )

    events_box.delete(
        "1.0",
        tk.END
    )

    events_box.insert(
        tk.END,
        "Monitoring started...\n\n"
    )

    events_box.config(
        state=tk.DISABLED
    )

    monitor_thread = threading.Thread(
        target=monitor_files,
        daemon=True
    )

    monitor_thread.start()


# ========================================
# STOP MONITOR
# ========================================

def stop_monitor():

    global monitoring

    if not monitoring:
        return

    stop_event.set()

    monitoring = False

    status_label.config(
        text="MONITORING STOPPED"
    )

    start_button.config(
        state=tk.NORMAL
    )

    stop_button.config(
        state=tk.DISABLED
    )

    create_baseline_button.config(
        state=tk.NORMAL
    )

    check_integrity_button.config(
        state=tk.NORMAL
    )

    clear_events_button.config(
        state=tk.NORMAL
    )

    create_report()


# ========================================
# CREATE SECURITY REPORT
# ========================================

def create_report():

    os.makedirs(
        REPORTS_FOLDER,
        exist_ok=True
    )

    stop_time = datetime.now()

    filename = (
        "security_report_"
        + stop_time.strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
        + ".txt"
    )

    report_path = os.path.join(
        REPORTS_FOLDER,
        filename
    )

    total_alerts = (
        new_count
        + modified_count
        + deleted_count
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "========================================\n"
        )

        file.write(
            "       SECURITY EVENT REPORT\n"
        )

        file.write(
            "========================================\n\n"
        )

        file.write(
            "Monitoring Session\n"
        )

        file.write(
            "------------------\n"
        )

        if session_start:

            file.write(
                f"Started : "
                f"{session_start.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

        file.write(
            f"Stopped : "
            f"{stop_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        file.write(
            "Event Summary\n"
        )

        file.write(
            "-------------\n"
        )

        file.write(
            f"New files       : {new_count}\n"
        )

        file.write(
            f"Modified files  : {modified_count}\n"
        )

        file.write(
            f"Deleted files   : {deleted_count}\n"
        )

        file.write(
            f"Total alerts    : {total_alerts}\n\n"
        )

        file.write(
            "Event History\n"
        )

        file.write(
            "-------------\n"
        )

        if not event_history:

            file.write(
                "No security events detected.\n"
            )

        else:

            for event in event_history:

                file.write(
                    f"[{event['time']}] "
                    f"{event['type']:<10} : "
                    f"{event['filename']}\n"
                )

                if event["type"] == "MODIFIED":

                    file.write(
                        f"    Previous SHA-256 : "
                        f"{event['previous_hash']}\n"
                    )

                    file.write(
                        f"    Current SHA-256  : "
                        f"{event['current_hash']}\n\n"
                    )

                elif event["type"] == "NEW FILE":

                    file.write(
                        f"    Current SHA-256  : "
                        f"{event['current_hash']}\n\n"
                    )

                elif event["type"] == "DELETED":

                    file.write(
                        f"    Previous SHA-256 : "
                        f"{event['previous_hash']}\n\n"
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

    report_label.config(
        text=(
            "Latest Report:\n"
            f"{os.path.basename(report_path)}"
        )
    )


# ========================================
# VIEW LATEST REPORT
# ========================================

def view_report():

    if not os.path.exists(
        REPORTS_FOLDER
    ):

        messagebox.showinfo(
            "Report",
            "No security reports found."
        )

        return

    reports = []

    for filename in os.listdir(
        REPORTS_FOLDER
    ):

        if (
            filename.startswith(
                "security_report_"
            )
            and filename.endswith(
                ".txt"
            )
        ):

            reports.append(filename)

    if not reports:

        messagebox.showinfo(
            "Report",
            "No security reports found."
        )

        return

    reports.sort(
        key=lambda x: os.path.getmtime(
            os.path.join(
                REPORTS_FOLDER,
                x
            )
        ),
        reverse=True
    )

    latest_report = os.path.join(
        REPORTS_FOLDER,
        reports[0]
    )

    try:

        os.startfile(
            latest_report
        )

    except Exception as error:

        messagebox.showerror(
            "Error",
            f"Could not open report.\n\n{error}"
        )


# ========================================
# CLOSE APPLICATION
# ========================================

def close_application():

    global monitoring

    if monitoring:

        stop_event.set()

        monitoring = False

    root.destroy()


# ========================================
# CREATE GUI
# ========================================

root = tk.Tk()

root.title(
    "File Integrity Monitor"
)

root.geometry(
    "900x820"
)

root.resizable(
    False,
    False
)


# ========================================
# TITLE
# ========================================

title_label = tk.Label(
    root,
    text="FILE INTEGRITY MONITOR",
    font=("Arial", 24, "bold")
)

title_label.pack(
    pady=15
)


subtitle_label = tk.Label(
    root,
    text="SHA-256 Based File Security System",
    font=("Arial", 11)
)

subtitle_label.pack(
    pady=2
)


# ========================================
# STATUS
# ========================================

status_label = tk.Label(
    root,
    text="MONITORING STOPPED",
    font=("Arial", 15, "bold")
)

status_label.pack(
    pady=8
)


# ========================================
# PROJECT INFORMATION
# ========================================

info_frame = tk.Frame(
    root,
    relief="solid",
    borderwidth=1
)

info_frame.pack(
    padx=20,
    pady=8,
    fill="x"
)


folder_label = tk.Label(
    info_frame,
    text=(
        "Protected Folder:\n"
        f"{PROTECTED_FOLDER}"
    ),
    font=("Arial", 9),
    anchor="w",
    justify="left"
)

folder_label.pack(
    padx=10,
    pady=6,
    anchor="w"
)


baseline_status_label = tk.Label(
    info_frame,
    text="Baseline: NOT CREATED",
    font=("Arial", 9, "bold"),
    anchor="w",
    justify="left"
)

baseline_status_label.pack(
    padx=10,
    pady=4,
    anchor="w"
)


# ========================================
# STATISTICS
# ========================================

stats_frame = tk.Frame(
    root
)

stats_frame.pack(
    pady=12
)


protected_label = tk.Label(
    stats_frame,
    text=f"Protected Files\n{len(baseline)}",
    font=("Arial", 12),
    width=19,
    height=3,
    relief="solid"
)

protected_label.grid(
    row=0,
    column=0,
    padx=5
)


new_label = tk.Label(
    stats_frame,
    text="New Files\n0",
    font=("Arial", 12),
    width=19,
    height=3,
    relief="solid"
)

new_label.grid(
    row=0,
    column=1,
    padx=5
)


modified_label = tk.Label(
    stats_frame,
    text="Modified Files\n0",
    font=("Arial", 12),
    width=19,
    height=3,
    relief="solid"
)

modified_label.grid(
    row=0,
    column=2,
    padx=5
)


deleted_label = tk.Label(
    stats_frame,
    text="Deleted Files\n0",
    font=("Arial", 12),
    width=19,
    height=3,
    relief="solid"
)

deleted_label.grid(
    row=1,
    column=0,
    padx=5,
    pady=8
)


alerts_label = tk.Label(
    stats_frame,
    text="Security Alerts\n0",
    font=("Arial", 12),
    width=19,
    height=3,
    relief="solid"
)

alerts_label.grid(
    row=1,
    column=1,
    padx=5,
    pady=8
)


# ========================================
# SECURITY EVENTS
# ========================================

events_title = tk.Label(
    root,
    text="SECURITY EVENTS",
    font=("Arial", 15, "bold")
)

events_title.pack(
    pady=5
)


events_box = tk.Text(
    root,
    width=98,
    height=10,
    font=("Consolas", 9)
)

events_box.pack(
    padx=20,
    pady=5
)

events_box.insert(
    tk.END,
    "No security events detected.\n"
)

events_box.config(
    state=tk.DISABLED
)


# ========================================
# BASELINE BUTTONS
# ========================================

management_frame = tk.Frame(
    root
)

management_frame.pack(
    pady=7
)


create_baseline_button = tk.Button(
    management_frame,
    text="CREATE BASELINE",
    width=18,
    height=2,
    command=create_baseline
)

create_baseline_button.grid(
    row=0,
    column=0,
    padx=5
)


check_integrity_button = tk.Button(
    management_frame,
    text="CHECK INTEGRITY",
    width=18,
    height=2,
    command=check_integrity
)

check_integrity_button.grid(
    row=0,
    column=1,
    padx=5
)


clear_events_button = tk.Button(
    management_frame,
    text="CLEAR EVENTS",
    width=18,
    height=2,
    command=clear_events
)

clear_events_button.grid(
    row=0,
    column=2,
    padx=5
)


# ========================================
# MONITOR BUTTONS
# ========================================

button_frame = tk.Frame(
    root
)

button_frame.pack(
    pady=7
)


start_button = tk.Button(
    button_frame,
    text="START MONITOR",
    width=18,
    height=2,
    command=start_monitor
)

start_button.grid(
    row=0,
    column=0,
    padx=5
)


stop_button = tk.Button(
    button_frame,
    text="STOP MONITOR",
    width=18,
    height=2,
    command=stop_monitor,
    state=tk.DISABLED
)

stop_button.grid(
    row=0,
    column=1,
    padx=5
)


report_button = tk.Button(
    button_frame,
    text="VIEW REPORT",
    width=18,
    height=2,
    command=view_report
)

report_button.grid(
    row=0,
    column=2,
    padx=5
)


# ========================================
# REPORT LABEL
# ========================================

report_label = tk.Label(
    root,
    text="No report generated in this session.",
    font=("Arial", 9)
)

report_label.pack(
    pady=5
)


# ========================================
# INITIAL GUI STATUS
# ========================================

update_status_information()


# ========================================
# EVENT PROCESSING
# ========================================

root.after(
    200,
    process_events
)


# ========================================
# CLOSE EVENT
# ========================================

root.protocol(
    "WM_DELETE_WINDOW",
    close_application
)


# ========================================
# START GUI
# ========================================

root.mainloop()