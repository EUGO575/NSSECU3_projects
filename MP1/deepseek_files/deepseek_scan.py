#!/usr/bin/env python3
"""
YARA Drive Scanner
Scans the entire E:\ drive against YARA rules from a specified directory.
Outputs matches to a CSV file, grouped by the source rule file.
"""

import os
import sys
import csv
import yara
from tqdm import tqdm

# ------------------------------------------------------------------------------
# Configuration (adjust as needed)
RULES_DIR = r"../scanner_rules"          # Directory containing .yar files
OUTPUT_CSV = "deepseek_scan_results.csv"          # Output CSV file
# ------------------------------------------------------------------------------


def compile_rules(rules_dir):
    """
    Compile all .yar files in the given directory, using the filename as the namespace.
    Declare 'filename' as an external variable so rules can reference it.
    Returns a yara.Rules object, or exits on failure.
    """
    if not os.path.isdir(rules_dir):
        print(f"Error: Rules directory '{rules_dir}' does not exist.")
        sys.exit(1)

    # Collect all .yar files
    yar_files = {}
    for filename in os.listdir(rules_dir):
        if filename.lower().endswith('.yar'):
            filepath = os.path.join(rules_dir, filename)
            # Use the filename (without path) as the namespace
            yar_files[filename] = filepath

    if not yar_files:
        print(f"No .yar files found in '{rules_dir}'.")
        sys.exit(1)

    print(f"Found {len(yar_files)} rule file(s). Compiling...")
    try:
        # Declare external variables (filename) so rules can use them.
        # Provide a dummy value; the actual value will be supplied at match time.
        rules = yara.compile(
            filepaths=yar_files,
            externals={'filename': ''}   # Tell compiler 'filename' is external
        )
        print("Compilation successful.")
        return rules
    except yara.SyntaxError as e:
        print(f"Syntax error in rule file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error during compilation: {e}")
        sys.exit(1)


def scan_file(file_path, rules):
    """
    Scan a single file with the given compiled rules.
    Returns a set of namespaces (source .yar filenames) that matched.
    If the file cannot be accessed, returns an empty set.
    """
    try:
        # Provide the actual filename at match time
        matches = rules.match(
            file_path,
            externals={'filename': os.path.basename(file_path)}
        )
        # Extract unique namespaces from matches
        namespaces = {m.namespace for m in matches}
        return namespaces
    except (yara.Error, PermissionError, OSError):
        # Skip files that cannot be read (permission denied, locked, etc.)
        return set()
    except Exception:
        # Catch-all for any other unexpected errors
        return set()


def get_first_50_bytes_hex(file_path):
    """
    Read the first 50 bytes of a file and return them as a hexadecimal string.
    On error, returns a placeholder message.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read(50)
            return data.hex()
    except Exception:
        return "ERROR_READING"


def main():
    # 1. Compile all rules
    rules = compile_rules(RULES_DIR)

    # 2. Prepare CSV output (collect rows in memory, then sort)
    rows = []
    fieldnames = ['File Location', 'Filename', 'YARA Rule Hit', 'First 50 Bytes']

    # 3. Walk through E:\ drive
    print("Scanning E:\ drive. This may take a long time...")
    # Use tqdm to show progress (total unknown, updates per file)
    with tqdm(desc="Scanning files", unit="files") as pbar:
        for root, dirs, files in os.walk(r"E:\\"):
            for filename in files:
                full_path = os.path.join(root, filename)
                # Scan the file
                namespaces = scan_file(full_path, rules)
                if namespaces:
                    # File matched at least one rule
                    first_50 = get_first_50_bytes_hex(full_path)
                    for ns in namespaces:
                        rows.append({
                            'File Location': root,
                            'Filename': filename,
                            'YARA Rule Hit': ns,
                            'First 50 Bytes': first_50
                        })
                pbar.update(1)   # update progress bar

    # 4. Sort rows by the "YARA Rule Hit" column
    rows.sort(key=lambda row: row['YARA Rule Hit'])

    # 5. Write to CSV
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Scan complete. Results written to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()