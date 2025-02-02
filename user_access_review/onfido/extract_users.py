import csv
import re
import sys

import fitz

if len(sys.argv) < 2:
    print("Usage: python extract_users.py <pdf path>")
    sys.exit(1)

pdf_path = sys.argv[1]
csv_path = "onfido_users.csv"

doc = fitz.open(pdf_path)
users = []
deactivated_section = False

for page in doc:
    text = page.get_text("text")
    lines = text.split("\n")

    for i in range(len(lines)):
        line = lines[i].strip()
        if "Deactivated users" in line:
            deactivated_section = True
            break

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        if re.search(email_pattern, line):
            name = lines[i - 1].strip() if i > 0 else "Unknown"
            email = line
            role = lines[i + 1].strip() if i + 1 < len(lines) else "Unknown"
            users.append((name, email, role))

    if deactivated_section:
        break

with open(csv_path, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Name", "Email", "Role"])
    writer.writerows(users)
