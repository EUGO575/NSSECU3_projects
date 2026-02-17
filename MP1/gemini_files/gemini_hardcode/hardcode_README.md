---

# Gemini Static Signature Scanner

This is a specialized, high-speed YARA scanner designed to identify specific files that match **hardcoded** criteria. Unlike general malware scanners that look for patterns, this version is optimized to find exact files based on their metadata and static byte signatures.

## 🔍 How It Works

The scanner uses a two-stage detection process to maximize speed:

1. **Size Pre-Filtering:** The script parses your `file_sigs.yar` file and extracts every `filesize == X` condition. Before running the YARA engine, it checks the size of every file on your disk. If the size doesn't match a rule exactly, the file is skipped instantly.
2. **Signature Matching:** For files that pass the size check, the script performs a deep scan for the specific byte sequences (hex) and external variables (like filenames) defined in your rules.

---

## 🛠️ Configuration

Edit these variables in the script to point to your target:

* `TARGET_PATH`: The directory to scan (e.g., `r'C:\Program Files (x86)'`).
* `RULES_FILE`: The path to your `.yar` signature file.
* `MAX_FILE_SIZE`: A safety cap to prevent the script from hanging on massive files.

---

## ⚠️ The "Hardcoded" Limitation (Fragility)

This scanner is designed for **exact-match integrity checking**. Because the rules are strictly defined, the detection is easily broken by any modification to the target file:

### 1. Changing the Filename

If a rule relies on the `filename` external variable (e.g., matching a regex like `File\d{3}`), simply renaming `File123.dat` to `Data123.dat` will cause the rule to fail.

### 2. Modifying the First 50 Bytes

Most file signatures (magic bytes) reside at the very beginning of the file.

* **The Break:** If a rule looks for a specific hex string in the first 50 bytes, changing even **one single byte** (e.g., changing `4D 5A` to `4D 5B`) will result in a "No Match."
* **The Result:** The file will be completely ignored by the scanner, even if the rest of the file content remains malicious or relevant.

### 3. Altering File Size

Since this version uses a **size pre-filter**, if a file is modified in a way that adds or removes even one byte of data, the script will skip it during the "Fast Discovery Phase" before the YARA engine even looks at it.

---

## 🚀 Installation & Execution

1. **Install dependencies:**
```bash
pip install yara-python tqdm

```


2. **Run with Elevation:**
To scan protected directories like `C:\Program Files (x86)`, run your terminal as **Administrator**:
```bash
python scanner_static.py

```



---

## 📊 Output

Matches are saved to `gemini_scan_results.csv`, providing the exact path, size, and the specific rule/description triggered.
