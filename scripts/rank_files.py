#!/usr/bin/env python3
"""
rank_files.py

Scan a directory of php files, compute per-file stats (unsafe line count, taint_count, max_prob, mean_prob)
and write a CSV for prioritization. Also includes a ready-to-run detect_lines.py command per file.

Usage:
python scripts/rank_files.py --dir data/train/unsafe --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --threshold 0.713 --out results/ranked_files.csv
"""

import argparse
import pickle
import csv
from pathlib import Path
import numpy as np
from tqdm import tqdm
import importlib.util

# Dynamically import detect_lines.py to reuse predict_file
spec = importlib.util.spec_from_file_location("detect_lines", "scripts/detect_lines.py")
dl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dl)

detect_fn = dl.predict_file  # make sure this function exists in detect_lines.py


def summarize_file(path, model, vectorizer, threshold):
    """Run per-line detection and summarize the file"""
    results = detect_fn(model, vectorizer, str(path), threshold=threshold)
    probs = [r[3] for r in results]
    taint_counts = sum(1 for r in results if r[4])  # taint report count
    unsafe_lines = sum(1 for r in results if r[2] == "unsafe")
    max_prob = float(max(probs)) if probs else 0.0
    mean_prob = float(np.mean(probs)) if probs else 0.0

    # Add command to rerun the file manually
    detect_cmd = (
        f"python scripts/detect_lines.py "
        f"--file {path} "
        f"--model models/logreg_model.pkl "
        f"--vectorizer models/tfidf_vectorizer.pkl "
        f"--threshold {threshold}"
    )

    return {
        "path": str(path),
        "unsafe_lines": unsafe_lines,
        "taint_count": taint_counts,
        "max_prob": max_prob,
        "mean_prob": mean_prob,
        "total_lines": len(results),
        "detect_command": detect_cmd
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--vectorizer", required=True)
    parser.add_argument("--threshold", type=float, default=0.713)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    # Load model and vectorizer
    with open(args.model, "rb") as f:
        model = pickle.load(f)
    with open(args.vectorizer, "rb") as f:
        vectorizer = pickle.load(f)

    php_files = list(Path(args.dir).rglob("*.php"))
    rows = []

    for p in tqdm(php_files, desc="Scanning files"):
        summary = summarize_file(p, model, vectorizer, args.threshold)
        rows.append(summary)

    # Sort by taint_count desc, then max_prob desc
    rows_sorted = sorted(rows, key=lambda r: (r["taint_count"], r["max_prob"], r["unsafe_lines"]), reverse=True)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "path",
                "taint_count",
                "unsafe_lines",
                "max_prob",
                "mean_prob",
                "total_lines",
                "detect_command",
            ],
        )
        writer.writeheader()
        writer.writerows(rows_sorted)

    print(f"\n✅ Wrote ranked CSV to {args.out}")
    print("💡 Each row now includes a ready-to-run detect_lines.py command!")


if __name__ == "__main__":
    main()
