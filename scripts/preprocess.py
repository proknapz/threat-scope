#!/usr/bin/env python3
"""
preprocess.py

Preprocess PHP files listed in a manifest CSV.

Usage:
  python preprocess.py --manifest manifests/train_manifest.csv --base_dir data/train --out preprocessed/train_processed.csv
"""
import pandas as pd
from pathlib import Path
import argparse
from tqdm import tqdm
import re

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"Failed to read {file_path}: {e}")
        return ""

def normalize_php_code(code):
    # Remove comments
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"#.*", "", code)
    # Collapse whitespace
    code = re.sub(r"\s+", " ", code)
    return code.strip()

def preprocess_manifest(manifest_csv, base_dir, out_csv):
    df = pd.read_csv(manifest_csv)
    base_dir = Path(base_dir)
    codes, labels, splits, projects = [], [], [], []

    for _, row in tqdm(df.iterrows(), total=len(df), desc="Preprocessing"):
        file_path = base_dir / row['filename']
        if not file_path.exists():
            print(f"Warning: file does not exist: {file_path}")
            code = ""
        else:
            code = read_file(file_path)
            code = normalize_php_code(code)
        codes.append(code)
        labels.append(row['label'])
        splits.append(row['split'])
        projects.append(row['project'])

    df_out = pd.DataFrame({
        "code": codes,
        "label": labels,
        "split": splits,
        "project": projects
    })
    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(out_csv, index=False)
    print(f"Preprocessed CSV saved to {out_csv}")
    print(df_out.head())

def main():
    parser = argparse.ArgumentParser(description="Preprocess PHP files from manifest CSV")
    parser.add_argument("--manifest", required=True, help="Input manifest CSV")
    parser.add_argument("--base_dir", required=True, help="Base directory of PHP files")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()
    preprocess_manifest(args.manifest, args.base_dir, args.out)

if __name__ == "__main__":
    main()
