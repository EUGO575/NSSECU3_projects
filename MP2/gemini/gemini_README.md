# HOW TO RUN
1. **Generate baseline_hashes**
```bash
python baseline_generator.py
```
## Configurable Values(Hardcoded)
| Variable           | Description                      | Default Value           |
| -------------------| -------------------------------- | ----------------------- |
| `TARGET_DIRECTORY` | Path to target directory         | `"baseline_hashes.csv"` |
| `OUTPUT_FILE`      | Path to outputfile               | `"E:`                   |

Output Hash CSV
The generated baseline.csv will contain:

```Filename,Absolute_Path,SHA256```

2. **Run as Administrator:**
```bash
python gemini_hash_scan_v3.py <scan_directory>


```

## Configurable Values(Hardcoded)
| Variable         | Description                      | Default Value           |
| ---------------- | -------------------------------- | ----------------------- |
| `BASELINE_CSV`   | Path to baseline CSV file        | `"baseline_hashes.csv"` |
| `SCAN_TARGET_DIR`| Path to scan target              | `"E:`                   |            
| `REPORT_FILE`    | Output CSV file for scan results | `"scan_results.csv"`    |


Example of options
```bash
python gemini_hash_scan_v3.py 
```

## Output CSV Format

Matches are written to:
```filename_results.csv```

With headers:
```Timestamp,Detected_Hash,File_Type,Original_Reference_Path,Current_Location```

Each match includes:
•Detection timestamp
•SHA256 hash
•Identified file type
•Original reference path(s) from baseline
•Current detected location

## ✅ Notes / Tips
•The scanner only processes files with no extension and size < 15MB.<br>
•The progress bar shows percentage, elapsed time, and ETA.<br>
•If no matches are found, the script will still generate a summary and execution stats.  
