import os
import hashlib
import csv
import time
import datetime
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Magic Number Signatures for File Identification
FILE_SIGNATURES = {
    "7f454c46": "ELF Executable",
    "4d5a": "Windows Executable (PE)",
    "25504446": "PDF Document",
    "ffd8ff": "JPEG Image",
    "89504e47": "PNG Image",
    "504b0304": "ZIP/Archive",
    "2321": "Shebang Script (!#)",
    "52617221": "RAR Archive",
    "1f8b08": "GZIP Archive"
}

def identify_filetype(file_path):
    """Reads the first few bytes to identify the file type via magic numbers."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16).hex()
            for signature, label in FILE_SIGNATURES.items():
                if header.startswith(signature):
                    return label
        return "Unknown/None"
    except:
        return "Error"

def load_baseline(csv_path):
    """Loads the baseline CSV into a dictionary."""
    reference_db = {}
    print(f"[*] Loading baseline from {csv_path}...")
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                reference_db[row['SHA256']] = row['Absolute_Path']
    except FileNotFoundError:
        print(f"[!] Error: Baseline file {csv_path} not found.")
        sys.exit(1)
    return reference_db

def hash_worker(file_path):
    """Computes SHA256 and identifies file type."""
    file_type = identify_filetype(file_path)
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data: break
                sha256.update(data)
        
        return file_path, sha256.hexdigest(), file_type, False
    except (PermissionError, OSError):
        return file_path, None, None, True

def print_progress_bar(iteration, total, start_time, prefix='', length=40, fill='█'):
    """Progress bar with Elapsed and Estimated Time Arrival (ETA)."""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_len = int(length * iteration // total)
    bar = fill * filled_len + '-' * (length - filled_len)
    
    elapsed_time = time.time() - start_time
    if iteration > 0:
        eta_seconds = (elapsed_time / iteration) * (total - iteration)
        eta_str = str(datetime.timedelta(seconds=int(eta_seconds)))
    else:
        eta_str = "--:--:--"
        
    elapsed_str = str(datetime.timedelta(seconds=int(elapsed_time)))
    
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% [Elapsed: {elapsed_str} | ETA: {eta_str}]')
    sys.stdout.flush()
    if iteration == total: print()

def scan_directory_concurrently(scan_dir, reference_db, output_report):
    print(f"[*] Starting scan: {scan_dir}")
    print("[*] Filtering: No Extension AND Size < 15MB")
    
    detected_matches = []
    files_to_scan = []
    # This will now only track filetypes of MATCHED files
    type_counts = {} 
    SIZE_LIMIT = 15 * 1024 * 1024 

    # 1. Build filtered file list
    for root, _, files in os.walk(scan_dir):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext == "": 
                abs_path = os.path.join(root, file)
                try:
                    if os.path.getsize(abs_path) < SIZE_LIMIT:
                        files_to_scan.append(abs_path)
                except (PermissionError, OSError):
                    continue
            
    total_files = len(files_to_scan)
    if total_files == 0:
        print("[!] No files matched the criteria.")
        return

    # 2. Parallel Processing
    max_threads = min(32, (os.cpu_count() or 1) * 5)
    processed = 0
    start_time = time.time()
    
    print_progress_bar(0, total_files, start_time, prefix='Scanning:')

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(hash_worker, f): f for f in files_to_scan}
        for future in as_completed(futures):
            path, h_hash, f_type, err = future.result()
            
            if not err:
                if h_hash in reference_db:
                    # UPDATED: Increment count ONLY if it exists in the baseline
                    type_counts[f_type] = type_counts.get(f_type, 0) + 1
                    
                    sys.stdout.write('\r' + ' ' * 100 + '\r') 
                    print(f"[!] MATCH: {path} (Type: {f_type})")
                    
                    detected_matches.append({
                        'Timestamp': datetime.datetime.now().isoformat(),
                        'Detected_Hash': h_hash,
                        'File_Type': f_type,
                        'Original_Reference_Path': reference_db[h_hash],
                        'Current_Location': path
                    })
            
            processed += 1
            print_progress_bar(processed, total_files, start_time, prefix='Scanning:')

    # 3. Report Generation
    if detected_matches:
        with open(output_report, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['Timestamp', 'Detected_Hash', 'File_Type', 'Original_Reference_Path', 'Current_Location']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(detected_matches)
        print(f"\n[+] Found {len(detected_matches)} matches. Saved to {output_report}")
        
        # Print the Filetype Summary Table only if matches were found
        print("\n" + "="*45)
        print(f"{'Matched Filetype Summary':^45}")
        print("="*45)
        print(f"{'Filetype':<30} | {'Count':<10}")
        print("-" * 45)
        for ftype in sorted(type_counts, key=type_counts.get, reverse=True):
            print(f"{ftype:<30} | {type_counts[ftype]:<10}")
        print("="*45 + "\n")
    else:
        print("\n[+] Scan finished. No matches found.")

if __name__ == "__main__":
    BASELINE_CSV = "baseline_hashes.csv"
    SCAN_TARGET_DIR = r"C:\Users\Vigilante"  
    REPORT_FILE = "scan_results.csv"

    db = load_baseline(BASELINE_CSV)
    scan_directory_concurrently(SCAN_TARGET_DIR, db, REPORT_FILE)