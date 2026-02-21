import os
import csv

def extract_file_headers(directory_path, output_csv, byte_count=50):
    # Prepare the header for the CSV
    headers = ["File name", f"{byte_count} bytes"]
    
    try:
        # Get list of files in the directory
        files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]
        
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for filename in files:
                file_path = os.path.join(directory_path, filename)
                try:
                    with open(file_path, 'rb') as f:
                        # Read the specific number of bytes
                        raw_bytes = f.read(byte_count)
                        # Convert bytes to a readable hex string for the CSV
                        hex_string = raw_bytes.hex(sep=' ')
                        writer.writerow([filename, hex_string])
                except Exception as e:
                    writer.writerow([filename, f"Error reading file: {e}"])
                    
        print(f"Successfully created {output_csv}")

    except FileNotFoundError:
        print("The specified directory does not exist.")

# Usage
target_dir = './File'  # Replace with your directory path
output_file = 'file_headers.csv'
extract_file_headers(target_dir, output_file)