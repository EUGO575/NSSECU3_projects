### The "Benchmark" Prompt

"Act as a Python Security Engineer. I need you to write a high-performance directory scanner that uses **YARA rules** to identify specific files. The script must be optimized for speed when scanning large directories (like `C:\Program Files (x86)`).

**Technical Requirements:**

1. **Libraries:** Use `os`, `csv`, `yara`, `re`, and `tqdm` for a progress bar.
2. **Size Pre-Filtering (Crucial for Speed):** * The script should first parse the provided `.yar` file using regex to extract all instances of `filesize == [number]`.
* During the directory crawl (using `os.walk`), the script should only perform a YARA `match()` if the file’s actual disk size matches one of the sizes extracted from the rules.


3. **External Variables:** The YARA compilation and matching must support an external variable named `filename`. When matching, pass the `os.path.basename` of the current file to this external variable.
4. **Scanning Logic:**
* Implement a `MAX_FILE_SIZE` limit (default 100MB).
* Use `rules.match(filepath=...)` rather than loading file content into memory to ensure efficiency.
* Include a toggle to skip files with no extensions.


5. **Output:** * Provide a visual progress bar using `tqdm` during the scanning phase.
* Save findings to a CSV file with headers: `File_Path`, `File_Size`, `Rule`, and `Description` (extracted from the YARA rule metadata).


6. **Error Handling:** Ensure the script gracefully handles `PermissionError` or `OSError` during the file indexing and scanning phases.

Write the code in a clean, modular format with a configuration section at the top."

---
