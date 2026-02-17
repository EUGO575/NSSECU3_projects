# YARA Drive Scanner by Deepseek

A Python script that scans the entire `C:\` drive using YARA rules, logging any matches to a CSV file. The script dynamically loads all `.yar` files from a specified directory, compiles them (with the `filename` external variable declared), walks through every accessible file on the C: drive, and records matches.

## Features

- Compiles all `.yar` rules from a configurable directory.
- Uses the filename of each rule file as a **namespace** – the source file is recorded in the output.
- Declares `filename` as an external variable so rules can use conditions like `filename matches /pattern/`.
- Scans every file on `C:\` (with basic permission‑error skipping).
- Displays a progress bar using `tqdm`.
- Extracts the first 50 bytes of matching files (in hex) and includes them in the output.
- Outputs results to a CSV file, **grouped by the source rule file** (i.e., the "YARA Rule Hit" column).

## Requirements

- **Python 3.6+**
- **yara-python** – the official YARA module for Python
- **tqdm** – for the progress bar

Install the dependencies with:

```bash
pip install yara-python tqdm
```

> **Note:** On Windows, you may need to install the [YARA binaries](https://github.com/VirusTotal/yara/releases) or use a pre‑compiled wheel for `yara-python`. If `pip install yara-python` fails, try:
> ```bash
> pip install yara-python --no-cache-dir
> ```
> or download a suitable wheel from [PyPI](https://pypi.org/project/yara-python/#files).

## Configuration

Edit the following variables at the top of the script to match your environment:

```python
RULES_DIR = r"C:\scanner_rules"   # Directory containing your .yar files
OUTPUT_CSV = "scan_results.csv"   # Path for the output CSV file
```

- Place all your YARA rules (`.yar` files) in `RULES_DIR`.
- The script will use the **filename** of each `.yar` file as the namespace – that filename will appear in the "YARA Rule Hit" column when a rule from that file matches.

## Usage

1. **Prepare your rules** – ensure they are valid YARA syntax and, if they use the `filename` variable, it is spelled exactly `filename` (case‑sensitive).

2. **Run the script** (preferably as Administrator to access all files):

   ```bash
   python yara_drive_scanner.py
   ```

   The scan may take a very long time depending on the size of your drive and the number of files. The progress bar shows the number of files processed.

3. **When finished**, the results are written to the CSV file specified in `OUTPUT_CSV`. The rows are sorted by the "YARA Rule Hit" column so that all matches from the same rule file appear together.

## CSV Output Columns

| Column             | Description                                                                                 |
|--------------------|---------------------------------------------------------------------------------------------|
| `File Location`    | The full directory path where the matching file resides.                                    |
| `Filename`         | The name of the matching file.                                                              |
| `YARA Rule Hit`    | The **filename** of the `.yar` file that contained the matching rule (the namespace).       |
| `First 50 Bytes`   | The first 50 bytes of the file, represented as a hexadecimal string.                        |

If the first 50 bytes cannot be read (e.g., file is locked or access denied), the column will contain `"ERROR_READING"`.

## How External Variables Work

The script automatically declares the `filename` external variable during compilation. This allows rules to use conditions like:

```yara
condition:
    filename matches /File\d{3}/
```

The actual value of `filename` is supplied at scan time – it is the **base name** of the file being scanned (e.g., `File123.exe`). The built‑in `filesize` variable is automatically available and does not need to be declared.

If your rules require other external variables (e.g., `filepath`, `extension`), you must modify the script to declare them both in `yara.compile()` and in the `rules.match()` call.

## Error Handling

- Files that cannot be opened due to `PermissionError` or other OS errors are silently skipped – they do not halt the scan and are not recorded in the CSV.
- Syntax errors in any `.yar` file will cause the script to exit with an error message.
- If the rules directory does not exist or contains no `.yar` files, the script exits.

## Performance Considerations

- Scanning every file on a large drive can take hours. Consider narrowing the scan to specific folders if you need faster results.
- The script reads only the first 50 bytes of matching files – this minimises disk I/O for the hex extraction.
- Running with **administrative privileges** will allow access to more system files, but also increases the risk of matching legitimate system files. Use with caution.

## Example Rule

The following rule (saved as `Suspect_Group.yar`) will match files whose name matches `File` followed by three digits, have a specific header at offset 0, and a specific file size:

```yara
rule Suspect_Group_File046 {
    meta:
        description = "Matches File046 (MZ)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 80947 and filename matches /File\d{3}/
}
```

## Troubleshooting

- **"undefined identifier 'filename'"** – This error means the compiler did not know `filename` is external. Ensure you are using the version of the script that declares `externals={'filename': ''}` in the `yara.compile()` call.
- **"yara.Error: could not open file"** – Usually a permission issue; the script skips these files automatically.
- **No matches found** – Verify that your rules are correct and that the files you expect to match actually exist. Try testing a single rule on a small test folder first.
