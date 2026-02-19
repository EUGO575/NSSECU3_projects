#!/usr/bin/env python3
"""
Baseline Hash Generator

Recursively traverse a target directory and compute SHA-256 for every file.
Reads files in 4096-byte chunks. Writes CSV with headers:
Filename, Absolute_Path, SHA256

Prints execution time, total files processed, and total errors/skipped files.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import time
from typing import Iterator, Tuple


CHUNK_SIZE = 4096
DEFAULT_OUTPUT = "baseline_hashes.csv"


def iter_files(root: str) -> Iterator[Tuple[str, str]]:
    """
    Yield tuples of (filename, absolute_path) for files under root.
    Symlinks are not followed.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            abs_path = os.path.join(dirpath, fname)
            yield fname, abs_path


def compute_sha256(path: str) -> str:
    """Compute SHA-256 of a file reading in CHUNK_SIZE bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def generate_baseline(root: str, out_csv: str) -> Tuple[int, int, float]:
    """Traverse root, compute hashes, write to out_csv. Return (files, errors, elapsed)."""
    start = time.perf_counter()
    files_processed = 0
    errors = 0

    # Ensure output directory exists
    out_dir = os.path.dirname(os.path.abspath(out_csv)) or "."
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError:
        # Not fatal; writing may fail later
        pass

    with open(out_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(("Filename", "Absolute_Path", "SHA256"))

        for fname, abs_path in iter_files(root):
            try:
                # skip if not a file or unreadable
                if not os.path.isfile(abs_path):
                    errors += 1
                    continue
                sha256 = compute_sha256(abs_path)
                writer.writerow((fname, os.path.abspath(abs_path), sha256))
                files_processed += 1
            except (PermissionError, OSError):
                errors += 1
            except Exception:
                # Catch-all to avoid crashing on weird files
                errors += 1

    elapsed = time.perf_counter() - start
    return files_processed, errors, elapsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate baseline SHA-256 hashes for all files in a directory."
    )
    parser.add_argument(
        "target_directory",
        help="Directory to traverse for baseline hashing.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"CSV output path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args(argv)

    if not os.path.isdir(args.target_directory):
        print(f"Error: target_directory not found or not a directory: {args.target_directory}")
        return 2

    print(f"Generating baseline hashes under: {args.target_directory}")
    files_processed, errors, elapsed = generate_baseline(args.target_directory, args.output)

    print()
    print("Baseline generation complete.")
    print(f"Output CSV: {os.path.abspath(args.output)}")
    print(f"Total files processed: {files_processed}")
    print(f"Total errors/skipped: {errors}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
