import os
import yara
import csv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ================= CONFIG =================
RULES_DIR = "./"
TARGET_DRIVE = "E://"
OUTPUT_CSV = "Gpt_scan_results.csv"
MAX_READ_BYTES = 50
MAX_WORKERS = 8  # Adjust based on CPU (4–12 recommended)
# ==========================================

results_lock = Lock()
results = []


def compile_yara_rules(rules_directory):
    print("[*] Compiling YARA rules...")

    rule_files = {}
    for file in os.listdir(rules_directory):
        if file.lower().endswith(".yar"):
            full_path = os.path.join(rules_directory, file)
            rule_files[file] = full_path

    if not rule_files:
        raise Exception("No .yar files found.")

    rules = yara.compile(
        filepaths=rule_files,
        externals={
            "filename": "",   # declare external
            "filepath": ""    # optional
        }
    )
    for r in rules:
        print(f"   - {r.identifier}")

    print(f"[+] Successfully compiled {len(rule_files)} rule files.")
    return rules



def get_first_50_bytes_hex(filepath):
    try:
        with open(filepath, "rb") as f:
            return f.read(MAX_READ_BYTES).hex()
    except Exception:
        return ""


def scan_file(file_path, rules):
    """Scan a single file and record only the first matching YARA rule."""
    global results

    name = os.path.basename(file_path)
    root = os.path.dirname(file_path)

    try:
        matches = rules.match(
            file_path,
            externals={
                "filename": name,
                "filepath": file_path
            }
        )

        if matches:
            # Only take the first match
            first_match = matches[0]
            first_50_hex = get_first_50_bytes_hex(file_path)

            # Use lock to safely update shared results
            with results_lock:
                # Only add if file hasn't been added yet
                if not any(r["Filename"] == name for r in results):
                    results.append({
                        "File Location": root,
                        "Filename": name,
                        "YARA Rule Hit": first_match.namespace,
                        "First 50 Bytes (Hex)": first_50_hex
                    })

    except yara.Error:
        pass
    except PermissionError:
        pass
    except Exception:
        pass



def get_all_files(target_drive):
    file_list = []
    for root, dirs, files in os.walk(target_drive):
        for name in files:
            file_list.append(os.path.join(root, name))
    return file_list


def write_csv(results, output_path):
    print("\n[*] Writing CSV output...")

    results_sorted = sorted(results, key=lambda x: x["YARA Rule Hit"])

    fieldnames = [
        "File Location",
        "Filename",
        "YARA Rule Hit",
        "First 50 Bytes (Hex)"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results_sorted)

    print(f"[+] Results saved to: {output_path}")
    print(f"[+] Total Matches: {len(results_sorted)}")


def main():
    rules = compile_yara_rules(RULES_DIR)

    print("[*] Enumerating files...")
    all_files = get_all_files(TARGET_DRIVE)
    print(f"[+] Total files found: {len(all_files)}")

    print("[*] Starting multithreaded scan...\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        with tqdm(total=len(all_files), desc="Scanning", unit="file") as pbar:
            futures = [executor.submit(scan_file, f, rules) for f in all_files]

            for future in as_completed(futures):
                pbar.update(1)

    write_csv(results, OUTPUT_CSV)


if __name__ == "__main__":
    main()
