#!/usr/bin/env python3
"""
High-Speed Concurrent Scanner

- Loads baseline_hashes.csv into a dict for O(1) lookup.
- Scans a target directory but ONLY processes files that:
    1) Have NO extension, and
    2) File size < 15 MiB
- Identifies file type from header (magic numbers).
- Uses ThreadPoolExecutor for concurrent hashing + identification.
- Shows dynamic progress bar with percentage, elapsed, and ETA.
- Writes matches to scan_results.csv with headers:
    Timestamp, Detected_Hash, File_Type, Original_Reference_Path, Current_Location
- On completion prints an ASCII table summary of matched file types.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

# Constants
CHUNK_SIZE = 4096
MAX_SCAN_SIZE = 15 * 1024 * 1024  # 15 MiB
DEFAULT_BASELINE = "baseline_hashes.csv"
DEFAULT_OUTPUT = "scan_results.csv"
HEADER_READ = 512  # bytes to read for magic detection
LOCK = threading.Lock()


def load_baseline(path: str) -> Dict[str, List[str]]:
    """
    Load baseline CSV mapping SHA256 -> list of original reference paths.
    Expects CSV with headers Filename, Absolute_Path, SHA256
    """
    mapping: Dict[str, List[str]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                sha = (row.get("SHA256") or "").strip()
                original = (row.get("Absolute_Path") or "").strip()
                if sha:
                    mapping.setdefault(sha, []).append(original or "")
    except FileNotFoundError:
        print(f"Baseline file not found: {path}", file=sys.stderr)
        raise
    except Exception as exc:
        print(f"Error reading baseline file: {exc}", file=sys.stderr)
        raise
    return mapping


def file_has_no_extension(path: str) -> bool:
    """
    Determine if filename has no extension. Leading dots (e.g., .bashrc)
    are considered no-extension by os.path.splitext semantics.
    """
    _, ext = os.path.splitext(path)
    return ext == ""


def identify_file_type(header: bytes) -> str:
    """
    Identify file type from leading bytes. Returns a short label or "Unknown/None".
    """
    if not header:
        return "Unknown/None"
    h0 = header
    # Windows PE (MZ at start)
    if h0.startswith(b"MZ"):
        return "Windows PE"
    if h0.startswith(b"\x7fELF"):
        return "ELF"
    if h0.startswith(b"%PDF"):
        return "PDF"
    if h0.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if h0.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if h0.startswith(b"PK\x03\x04") or h0.startswith(b"PK\x05\x06") or h0.startswith(b"PK\x07\x08"):
        return "ZIP"
    if h0.startswith(b"\x1f\x8b"):
        return "GZIP"
    # Add more signatures here if desired
    return "Unknown/None"


def compute_sha256_for_file(path: str) -> str:
    """Compute SHA256 reading in CHUNK_SIZE chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def process_file(path: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Process a single file:
    - compute sha256
    - identify file type from header
    Returns a tuple: (sha256, file_type, error_message, current_abs_path)
    If error_message is not None then sha256/file_type may be empty.
    """
    try:
        abs_path = os.path.abspath(path)
        # read header
        with open(path, "rb") as fh:
            header = fh.read(HEADER_READ)
        f_type = identify_file_type(header)
        sha = compute_sha256_for_file(path)
        return sha, f_type, None, abs_path
    except (PermissionError, OSError) as exc:
        return "", "", f"{type(exc).__name__}: {exc}", path
    except Exception as exc:
        return "", "", f"Exception: {exc}", path


def gather_candidates(root: str) -> List[str]:
    """
    Walk directory tree and collect files that MATCH BOTH:
      - have no extension
      - size < MAX_SCAN_SIZE
    """
    candidates: List[str] = []
    for dirpath, _, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            try:
                if not os.path.isfile(full):
                    continue
                if not file_has_no_extension(fname):
                    continue
                size = os.path.getsize(full)
                if size < MAX_SCAN_SIZE:
                    candidates.append(full)
            except (OSError, PermissionError):
                # skip unreadable files
                continue
    return candidates


def format_timespan(seconds: float) -> str:
    """Return H:MM:SS or M:SS for durations."""
    if seconds is None or math.isinf(seconds):
        return "N/A"
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


def print_progress(processed: int, total: int, start_time: float) -> None:
    """Print a single-line progress bar with percentage, elapsed, and ETA."""
    elapsed = time.perf_counter() - start_time
    perc = (processed / total * 100) if total else 100.0
    # ETA calculation: if processed==0, unknown
    eta = 0.0
    if processed > 0:
        eta = elapsed / processed * (total - processed)
    bar_len = 30
    filled = int(bar_len * (processed / total)) if total else bar_len
    bar = "#" * filled + "-" * (bar_len - filled)
    line = (
        f"\rProgress: [{bar}] {perc:6.2f}% "
        f"Processed: {processed}/{total} "
        f"Elapsed: {format_timespan(elapsed)} ETA: {format_timespan(eta)}"
    )
    # Clear to end of line (ANSI) then print (some terminals may ignore ANSI)
    sys.stdout.write("\033[K" + line)
    sys.stdout.flush()


def clear_progress_line() -> None:
    """Clear the current console line."""
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()


def write_match_csv_row(
    writer: csv.writer, sha: str, f_type: str, originals: List[str], current: str
) -> None:
    timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
    writer.writerow((timestamp, sha, f_type, ";".join(originals), current))


def ascii_summary_table(counts: Dict[str, int]) -> str:
    """Return a formatted ASCII table summarizing counts by file type."""
    if not counts:
        return "No matches found."
    rows = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    col1 = "File Type"
    col2 = "Count"
    w1 = max(len(col1), max(len(r[0]) for r in rows))
    w2 = max(len(col2), max(len(str(r[1])) for r in rows))
    sep = f"+-{'-' * w1}-+-{'-' * w2}-+"
    header = f"| {col1:<{w1}} | {col2:>{w2}} |"
    lines = [sep, header, sep]
    for ftype, cnt in rows:
        lines.append(f"| {ftype:<{w1}} | {cnt:>{w2}} |")
    lines.append(sep)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="High-speed concurrent scanner.")
    parser.add_argument("scan_directory", help="Directory to scan.")
    parser.add_argument(
        "--baseline",
        "-b",
        default=DEFAULT_BASELINE,
        help=f"Baseline CSV path (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Scan results CSV (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=max(4, (os.cpu_count() or 1) * 2),
        help="Number of worker threads to use (default: cpu_count * 2 or 4).",
    )
    args = parser.parse_args(argv)

    if not os.path.isdir(args.scan_directory):
        print(f"Scan directory not found: {args.scan_directory}", file=sys.stderr)
        return 2

    try:
        baseline = load_baseline(args.baseline)
    except Exception:
        return 3

    # Build candidate list
    print("Gathering candidate files (no extension AND size < 15 MiB)...")
    candidates = gather_candidates(args.scan_directory)
    total = len(candidates)
    print(f"Candidates found: {total}")

    # Prepare output CSV
    try:
        out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
        os.makedirs(out_dir, exist_ok=True)
        out_fh = open(args.output, "w", newline="", encoding="utf-8")
        writer = csv.writer(out_fh)
        writer.writerow(("Timestamp", "Detected_Hash", "File_Type", "Original_Reference_Path", "Current_Location"))
    except Exception as exc:
        print(f"Unable to open output CSV: {exc}", file=sys.stderr)
        return 4

    start = time.perf_counter()
    processed = 0
    errors = 0
    matches = 0
    matched_type_counts: Dict[str, int] = {}

    # Use ThreadPoolExecutor for IO-bound hashing
    with ThreadPoolExecutor(max_workers=args.workers) as exc:
        futures = {exc.submit(process_file, path): path for path in candidates}

        # Iterate as futures complete so we can update progress and write matches as discovered
        for fut in as_completed(futures):
            path = futures[fut]
            try:
                sha, f_type, err, abs_path = fut.result()
            except Exception as exc_err:
                # Unexpected error in worker
                sha, f_type, err, abs_path = "", "", f"WorkerException: {exc_err}", path

            processed += 1
            if err:
                errors += 1
            else:
                # Check match
                if sha in baseline:
                    originals = baseline[sha]
                    matches += 1
                    # Clear progress line, print match notification
                    clear_progress_line()
                    print(
                        f"[MATCH] {sha}  Type: {f_type}  Original(s): {len(originals)}  Current: {abs_path}"
                    )
                    # Write to CSV
                    try:
                        write_match_csv_row(writer, sha, f_type, originals, abs_path)
                        out_fh.flush()
                    except Exception:
                        # Non-fatal: continue
                        pass
                    # Update matched counts
                    matched_type_counts[f_type] = matched_type_counts.get(f_type, 0) + 1

            # Update progress bar
            print_progress(processed, total, start)

    # Final newline after progress
    sys.stdout.write("\n")
    out_fh.close()

    elapsed = time.perf_counter() - start
    print()
    print("Scan complete.")
    print(f"Baseline source: {os.path.abspath(args.baseline)}")
    print(f"Results CSV: {os.path.abspath(args.output)}")
    print(f"Total candidates scanned: {total}")
    print(f"Total processed (attempted): {processed}")
    print(f"Total matches: {matches}")
    print(f"Total errors/skipped: {errors}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print()

    # Print ASCII summary table for matched file types
    print("Matched file types summary:")
    print(ascii_summary_table(matched_type_counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
