import os
import csv
import yara
import re
from tqdm import tqdm  # Ensure this is installed: pip install tqdm

# ================= CONFIGURATION =================
TARGET_PATH = r'C:\Program Files (x86)'
RULES_FILE = 'file_sigs.yar'  # Updated to match your uploaded filename
OUTPUT_CSV = 'gemini_scan_results.csv'
MAX_FILE_SIZE = 100 * 1024 * 1024 # 100MB Limit (Adjust as needed)
SKIP_NO_EXTENSION = False # Set to True if you want to skip files without extensions
# =================================================

def get_target_sizes(yar_file):
    """
    Extracts file sizes from YARA rules to use as a pre-filter.
    Parses 'filesize == X' and 'filesize == X or filesize == Y'
    """
    sizes = set()
    print(f"[*] Analyzing rules for target sizes...")
    try:
        with open(yar_file, 'r', encoding='utf-8') as f:
            content = f.read()
            # Match all occurrences of 'filesize == [digits]'
            matches = re.findall(r'filesize\s*==\s*(\d+)', content)
            for size in matches:
                sizes.add(int(size))
    except Exception as e:
        print(f"[-] Could not parse sizes from rules: {e}")
    return sizes

def scan():
    if not os.path.exists(RULES_FILE):
        print(f"[-] Error: {RULES_FILE} not found.")
        return

    # 1. Load and Compile
    # FIX 1: Define 'filename' as an external string variable during compilation
    try:
        rules = yara.compile(filepath=RULES_FILE, externals={'filename': ''})
    except yara.SyntaxError as e:
        print(f"[-] YARA Compilation Error: {e}")
        return

    target_sizes = get_target_sizes(RULES_FILE)
    if not target_sizes:
        print("[-] Warning: No target sizes found in rules. The size pre-filter will block all files.")
        
    # 2. Fast Discovery Phase (Finding candidates)
    print(f"[*] Indexing files in {TARGET_PATH}... (Please wait)")
    candidate_files = []
    total_files_on_disk = 0

    for root, dirs, files in os.walk(TARGET_PATH):
        for file in files:
            total_files_on_disk += 1
            file_path = os.path.join(root, file)
            
            if SKIP_NO_EXTENSION and "." not in file:
                continue
                
            try:
                f_size = os.path.getsize(file_path)
                # Optimization: Only scan if size matches one of the rules
                if f_size in target_sizes and f_size <= MAX_FILE_SIZE:
                    candidate_files.append((file_path, f_size))
            except (PermissionError, OSError):
                continue

    print(f"[*] Found {total_files_on_disk} total files.")
    print(f"[*] Filtered down to {len(candidate_files)} candidates matching target sizes.")

    # 3. Targeted Scanning Phase
    results = []
    
    if candidate_files:
        pbar = tqdm(total=len(candidate_files), desc="Scanning Files", unit="file", colour="green")

        for file_path, f_size in candidate_files:
            try:
                # FIX 2: Pass the specific filename to the rule engine for this file
                # The regex /File\d{3}/ in your rule will run against this string
                matches = rules.match(
                    filepath=file_path, 
                    externals={'filename': os.path.basename(file_path)} 
                )
                
                if matches:
                    for m in matches:
                        results.append({
                            "File_Path": file_path,
                            "File_Size": f_size,
                            "Rule": m.rule,
                            "Description": m.meta.get('description', '')
                        })
            except Exception as e:
                # Optional: Print error if scanning fails
                # print(f"Error scanning {file_path}: {e}")
                pass
            pbar.update(1)
        
        pbar.close()
    else:
        print("[-] No candidates found to scan.")

    # 4. Save Results
    if results:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["File_Path", "File_Size", "Rule", "Description"])
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[+] Success! {len(results)} matches saved to {OUTPUT_CSV}")
    else:
        print("\n[-] No matches found.")

if __name__ == "__main__":
    scan()