#!/usr/bin/env python3
"""
preprocess.py

Read a manifest CSV listing PHP files, normalize each PHP file's code
(remove comments, strip string contents, collapse whitespace), and
write a processed CSV with columns: code,label,split,project

Usage:
  python scripts/prepare_data.py --manifest manifests/train_manifest.csv --base_dir data/train --out preprocessed/train_processed.csv
"""

import argparse
from pathlib import Path
import pandas as pd
import re
import csv

# Regexes
_RE_MULTI_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_SINGLE_COMMENT1 = re.compile(r"//.*")
_RE_SINGLE_COMMENT2 = re.compile(r"#.*")
_RE_DOUBLE_STR = re.compile(r'"(?:\\.|[^"\\])*"', re.DOTALL)
_RE_SINGLE_STR = re.compile(r"'(?:\\.|[^'\\])*'", re.DOTALL)
_RE_WHITESPACE = re.compile(r"\s+")

def read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[WARN] Failed to read {path}: {e}")
        return ""

def normalize_php_code(code: str) -> str:
    """Remove comments, strip string contents, collapse whitespace."""
    # remove multi-line comments
    code = _RE_MULTI_COMMENT.sub("", code)
    # remove single-line comments
    code = _RE_SINGLE_COMMENT1.sub("", code)
    code = _RE_SINGLE_COMMENT2.sub("", code)
    # replace string literals with empty quotes (preserve quote chars)
    code = _RE_DOUBLE_STR.sub('""', code)
    code = _RE_SINGLE_STR.sub("''", code)
    # collapse whitespace to single spaces
    code = _RE_WHITESPACE.sub(" ", code)
    return code.strip()

def preprocess_manifest(manifest_csv: Path, base_dir: Path, out_csv: Path):
    if not manifest_csv.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_csv}")

    df = pd.read_csv(manifest_csv, dtype=str, keep_default_na=False)
    # ensure expected columns exist or create defaults
    if 'filename' not in df.columns:
        raise ValueError("Manifest must contain a 'filename' column.")
    if 'label' not in df.columns:
        df['label'] = '0'
    if 'split' not in df.columns:
        df['split'] = 'none'
    if 'project' not in df.columns:
        # default project = parent folder name (or 'unknown')
        def infer_project(fn):
            p = Path(fn)
            if len(p.parts) >= 2:
                return p.parts[0]
            return 'unknown'
        df['project'] = df['filename'].apply(infer_project)

    codes = []
    for idx, row in df.iterrows():
        file_rel = row['filename']
        file_path = (base_dir / Path(file_rel))
        if not file_path.exists():
            print(f"[WARN] file missing: {file_path}")
            code = ""
        else:
            raw = read_file(file_path)
            code = normalize_php_code(raw)
        codes.append(code)

    out_df = pd.DataFrame({
        "code": codes,
        "label": df['label'],
        "split": df['split'],
        "project": df['project']
    })

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    # write with all fields quoted (so code with commas/quotes is safe)
    out_df.to_csv(out_csv, index=False, quoting=csv.QUOTE_ALL, encoding='utf-8')
    print(f"[OK] Saved preprocessed CSV to {out_csv}")
    print(out_df.head())

def main():
    parser = argparse.ArgumentParser(description="Preprocess PHP files from a manifest into a CSV")
    parser.add_argument("--manifest", required=True, help="Input manifest CSV path (must contain 'filename' column)")
    parser.add_argument("--base_dir", required=True, help="Base directory where files are located")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    preprocess_manifest(Path(args.manifest), Path(args.base_dir), Path(args.out))

if __name__ == "__main__":
    main()
