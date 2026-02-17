# Multithreaded YARA Scanner by ChatGPT

A high-speed forensic utility designed to scan entire drives using **multithreading** and **YARA rules**. This version maximizes CPU utilization to minimize scan times on large datasets.

---

## ⚡ Key Features

* **Parallel Processing:** Uses `ThreadPoolExecutor` to scan multiple files simultaneously.
* **Smart Compilation:** Automatically compiles all `.yar` files in the directory into separate namespaces.
* **Real-time Progress:** Integrated `tqdm` progress bar with file-per-second tracking.
* **Thread-Safe Logging:** Uses mutex locks to prevent data corruption during CSV export.
* **Hex Extraction:** Automatically captures the first 50 bytes of flagged files.

---

## 🛠️ Configuration

Adjust these constants at the top of the script:

* `MAX_WORKERS`: Set to **8** (default) or match your CPU core count for peak speed.
* `TARGET_DRIVE`: Path to scan (e.g., `E://`).
* `RULES_DIR`: Folder containing your `.yar` signature files.

---

## 🚀 Quick Start

1. **Install dependencies:**
```bash
pip install yara-python tqdm

```


2. **Run as Administrator:**
```bash
python gpt_scanner.py

```



---

## 📊 Output

Results are sorted by **YARA Rule Hit** and saved to `Gpt_scan_results.csv`, containing:

1. **File Location**
2. **Filename**
3. **YARA Rule Hit** (Namespace)
4. **First 50 Bytes (Hex)**

---
