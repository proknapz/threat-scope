#!/usr/bin/env python3
"""
preprocess.py

Line-level preprocessing for PHP files for ML line detection.
python scripts\preprocess.py --manifest manifests\train_manifest.csv --base_dir data\train --out preprocessed\train_linelevel.csv


"""
import pandas as pd
from pathlib import Path
import argparse
from tqdm import tqdm
import re

_double_quote_str = re.compile(r'"(?:\\.|[^"\\])*"', re.DOTALL)
_single_quote_str = re.compile(r"'(?:\\.|[^'\\])*'", re.DOTALL)

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"Failed to read {file_path}: {e}")
        return ""

def normalize_php_line(line):
    # Remove block comments (simplified, assumes single line or normalized block)
    line = re.sub(r"/\*.*?\*/", "", line)
    # Remove single-line comments
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"#.*", "", line)
    # Replace string literals with empty quotes
    line = _double_quote_str.sub('""', line)
    line = _single_quote_str.sub("''", line)
    # Collapse whitespace
    line = re.sub(r"\s+", " ", line)
    return line.strip()

def preprocess_manifest_line_level(manifest_csv, base_dir, out_csv):
    df = pd.read_csv(manifest_csv)
    base_dir = Path(base_dir)

    lines_list, labels_list, splits_list, projects_list, files_list, linenos_list = [], [], [], [], [], []

    for _, row in tqdm(df.iterrows(), total=len(df), desc="Preprocessing"):
        file_path = base_dir / row['filename']
        if not file_path.exists():
            print(f"Warning: file does not exist: {file_path}")
            continue
        content = read_file(file_path)
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            norm_line = normalize_php_line(line)
            if norm_line == "":
                continue  # skip empty lines
            lines_list.append(norm_line)
            labels_list.append(row['label'])
            splits_list.append(row['split'])
            projects_list.append(row['project'])
            files_list.append(str(file_path))
            linenos_list.append(lineno)

    df_out = pd.DataFrame({
        "file": files_list,
        "lineno": linenos_list,
        "line": lines_list,
        "label": labels_list,
        "split": splits_list,
        "project": projects_list
    })

    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(out_csv, index=False)
    print(f"Line-level preprocessed CSV saved to {out_csv}")
    print(df_out.head())

def main():
    parser = argparse.ArgumentParser(description="Line-level preprocess PHP files from manifest CSV")
    parser.add_argument("--manifest", required=True, help="Input manifest CSV")
    parser.add_argument("--base_dir", required=True, help="Base directory of PHP files")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    preprocess_manifest_line_level(args.manifest, args.base_dir, args.out)

if __name__ == "__main__":
    main()
