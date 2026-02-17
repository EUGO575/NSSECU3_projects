---

# Gemini YARA Scanner

A lightweight, high-performance Python script designed to scan local directories or entire drives (like `E:\` or `C:\`) using **YARA rules**. It identifies malicious or interesting files based on your custom rule sets and exports the findings into a structured CSV report.

## 🚀 Features

* **Namespace-Based Matching:** Uses the filename of each `.yar` file as a namespace, making it easy to identify which rule source triggered a detection.
* **Performance Optimized:** Includes a "Fast Discovery Phase" that indexes file metadata before scanning to handle large volumes of files efficiently.
* **Progress Tracking:** Uses `tqdm` to provide a real-time progress bar and estimated time remaining during the scan.
* **Forensic Metadata:** Automatically extracts and logs the **first 50 bytes (Hex)** of any flagged file for quick signature verification.
* **Safe Handling:** Respects file size limits (default 100MB) and gracefully skips system locks or permission errors.

---

## 🛠️ Setup & Installation

### 1. Prerequisites

Ensure you have Python 3.x installed. You will also need the `yara-python` and `tqdm` libraries.

```bash
pip install yara-python tqdm

```

### 2. Directory Structure

Place your script in a folder alongside a directory containing your YARA rules:

```text
📂 Project Folder
 ├── scanner.py             # The script provided
 ├── 📂 scanner_rules       # Put your .yar or .yara files here
 │    ├── malware_set1.yar
 │    └── obfuscation_rules.yar
 └── gemini_scan_results.csv # (Generated after scan)

```

---

## ⚙️ Configuration

You can modify the following variables directly in the `# ================= CONFIGURATION =================` section of the script:

| Variable | Description |
| --- | --- |
| `TARGET_PATH` | The drive or folder you want to scan (e.g., `'E:\'` or `'C:\Users'`). |
| `RULES_DIR` | The folder where your `.yar` files are stored. |
| `MAX_FILE_SIZE` | Files larger than this (in bytes) will be skipped to save time. |
| `SKIP_NO_EXTENSION` | Set to `True` to ignore files that do not have a file extension. |

---

## 📈 Usage

1. Open your terminal or command prompt.
2. **Note:** If scanning system drives (like `C:\`), run the terminal as **Administrator**.
3. Execute the script:
```bash
python scanner.py

```



### Output

The script generates `gemini_scan_results.csv` with the following columns:

* **File Location:** The directory path where the file was found.
* **Filename:** The name of the detected file.
* **YARA Rule Hit:** The specific rule file (namespace) that triggered the alert.
* **First 50 Bytes:** The hex header of the file for manual analysis.

---

## ⚠️ Important Considerations

* **Permissions:** Running without Administrator privileges may result in many "Permission Denied" errors when scanning system-protected folders.
* **Large Drives:** Scanning a full `C:\` drive can take significant time depending on your disk speed (SSD vs HDD) and the number of rules compiled.
