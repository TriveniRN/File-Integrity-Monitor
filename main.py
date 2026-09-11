import os
import hashlib
import json

# --------------------------------
# Settings
# --------------------------------

protected_folder = "protected_files"
baseline_folder = "baseline"
baseline_file = "baseline/baseline.json"

# --------------------------------
# Create baseline folder
# --------------------------------

os.makedirs(baseline_folder, exist_ok=True)

# --------------------------------
# Dictionary to store file hashes
# --------------------------------

baseline = {}

# --------------------------------
# Calculate SHA-256 for each file
# --------------------------------

for filename in os.listdir(protected_folder):

    file_path = os.path.join(protected_folder, filename)

    if os.path.isfile(file_path):

        with open(file_path, "rb") as file:
            file_data = file.read()

        file_hash = hashlib.sha256(file_data).hexdigest()

        baseline[filename] = file_hash

# --------------------------------
# Save baseline
# --------------------------------

with open(baseline_file, "w") as file:
    json.dump(baseline, file, indent=4)

# --------------------------------
# Display result
# --------------------------------

print("Baseline created successfully!")
print("Files monitored:", len(baseline))
print("Baseline saved to:", baseline_file)