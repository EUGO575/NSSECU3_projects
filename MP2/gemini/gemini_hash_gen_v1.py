import os
import hashlib
import csv
import time

def calculate_hash(file_path, buffer_size=4096):
    """
    Calculates the SHA256 hash for a given file.
    Reads in chunks to handle large files efficiently.
    """
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(buffer_size)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None

def generate_baseline(target_dir, output_csv):
    """
    Traverses the target directory and logs SHA256 file hashes to a CSV.
    """
    print(f"[*] Starting baseline generation for: {target_dir}")
    start_time = time.time()
    
    files_processed = 0
    errors = 0

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Filename', 'Absolute_Path', 'SHA256']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for root, _, files in os.walk(target_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                
                # Calculate single hash
                sha256_hash = calculate_hash(abs_path)
                
                if sha256_hash:
                    writer.writerow({
                        'Filename': file,
                        'Absolute_Path': abs_path,
                        'SHA256': sha256_hash
                    })
                    files_processed += 1
                else:
                    errors += 1

    elapsed = time.time() - start_time
    print(f"[-] Completed in {elapsed:.2f}s")
    print(f"[-] Processed: {files_processed} | Skipped/Errors: {errors}")
    print(f"[-] Output saved to: {output_csv}")

if __name__ == "__main__":
    TARGET_DIRECTORY = r"C:\Users\Vigilante\Desktop\MP2_test\File"  
    OUTPUT_FILE = "baseline_hashes.csv"
    
    generate_baseline(TARGET_DIRECTORY, OUTPUT_FILE)