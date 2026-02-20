# HOW TO RUN
1. **Generate baseline_hashes**
```bash
python baseline_generator.py <baseline_directory> -o baseline.csv
```
Output Hash CSV
The generated baseline.csv will contain:

Filename,Absolute_Path,SHA256

2. **Run as Administrator:**
```bash
python gpt_hash_scan_v1.py <scan_directory>


```

## Optional Arguments
| Option             | Description               | Default                     |
| ------------------ | ------------------------- | --------------------------- |
| `-b`, `--baseline` | Path to baseline CSV file | `baseline_hashes.csv`       |
| `-o`, `--output`   | Output CSV file           | `scan_results.csv`          |
| `-w`, `--workers`  | Number of worker threads  | `CPU count × 2` (minimum 4) |

Example of options
```bash
python gpt_hash_scan_v1.py E:\ -b known_hashes.csv -o results.csv -w 8
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
