#!/usr/bin/env python3
"""
load_data.py

Scan a directory containing `safe/` and `unsafe/` subfolders (including nested folders)
and produce a CSV manifest with relative paths.

Usage:
  python scripts/load_data.py --input_dir data/train --out manifests/train_manifest.csv
"""
from pathlib import Path
import pandas as pd
from tqdm import tqdm
import argparse

def gather_files(input_dir):
    input_dir = Path(input_dir)
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    rows = []
    for php_file in tqdm(list(input_dir.rglob("*.php")), desc="Scanning PHP files"):
        parts = php_file.parts

        # ✅ Determine label and label_name
        if "safe" in parts:
            label = 0
            label_name = "safe"
            project = "safe"
        elif "unsafe" in parts:
            label = 1
            label_name = "unsafe"
            project = "unsafe"
        else:
            label = -1
            label_name = "unknown"
            project = "unknown"

        # ✅ Store relative path to input_dir (use Windows-style backslashes)
        rel_path = php_file.relative_to(input_dir)
        rel_path_str = str(rel_path).replace("/", "\\")

        rows.append({
            "filename": rel_path_str,
            "label": label,
            "label_name": label_name,
            "project": project,
            "split": "none"
        })

    return pd.DataFrame(rows)

def main():
    parser = argparse.ArgumentParser(description="Create manifest CSV of PHP files")
    parser.add_argument("--input_dir", required=True, help="Directory containing PHP files")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    df = gather_files(args.input_dir)
    if df.empty:
        print("No PHP files found.")
        return

    df.to_csv(args.out, index=False)
    print(f"✅ Manifest CSV saved to {args.out}")
    print(df.head())

if __name__ == "__main__":
    main()
