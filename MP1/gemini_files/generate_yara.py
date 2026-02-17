import csv
from collections import defaultdict

# Configuration
INPUT_CSV = 'file_headers.csv'
OUTPUT_YAR = 'rules_v1.yar'
HEX_COLUMN = 'First_50_Hex'
SIZE_COLUMN = 'File_Size_Bytes'

def generate_deduplicated_rules():
    print(f"[+] Reading {INPUT_CSV}...")
    
    # Dictionary to store unique signatures
    # Key: (hex_string, file_size)
    # Value: List of filenames
    unique_signatures = defaultdict(list)
    
    try:
        with open(INPUT_CSV, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # 1. Get Hex and Size
                hex_str = row.get(HEX_COLUMN, '').strip().replace(' ', '')
                if not hex_str: continue

                try:
                    f_size = int(row.get(SIZE_COLUMN, 0))
                except ValueError:
                    continue

                # 2. Normalize Hex (Use full 50 bytes)
                if len(hex_str) > 100: 
                    hex_str = hex_str[:100]
                
                # 3. Add to dictionary (Group by Signature)
                unique_signatures[(hex_str, f_size)].append(row.get('Filename', 'Unknown'))

        # 4. Generate Rules from Unique Signatures
        with open(OUTPUT_YAR, mode='w', encoding='utf-8') as out:
            rule_count = 0
            
            for (hex_str, f_size), filenames in unique_signatures.items():
                # Create a unique rule name based on the first file in the group
                # (e.g., Suspect_Group_File024)
                primary_file = filenames[0]
                # Clean filename for rule name (alphanumeric only)
                safe_name = "".join(c for c in primary_file if c.isalnum())
                rule_name = f"Suspect_Group_{safe_name}"
                
                # Format hex for YARA
                yara_hex = ' '.join(hex_str[j:j+2] for j in range(0, len(hex_str), 2))
                
                # Create description listing all files
                desc = f"Matches {len(filenames)} files: {', '.join(filenames[:5])}"
                if len(filenames) > 5:
                    desc += f" and {len(filenames)-5} others."

                rule = f"""rule {rule_name} {{
    meta:
        description = "{desc}"
        author = "Forensics Deduplication Script"
        original_size = {f_size}
    strings:
        $header = {{ {yara_hex} }}
    condition:
        $header at 0 and filesize == {f_size}
}}
"""
                out.write(rule)
                rule_count += 1
                    
        print(f"[+] Successfully generated {rule_count} unique rules in '{OUTPUT_YAR}'")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    generate_deduplicated_rules()