#!/usr/bin/env python3
"""
predict.py
Predict if a PHP file is safe or unsafe using a trained model + vectorizer.
Usage:
python scripts/predict.py --file data/train/unsafe/example.php --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl
python scripts/predict.py --dir data/train --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --out results/predictions.csv

"""

import argparse
import pickle
from pathlib import Path
import re
from tqdm import tqdm


def read_file(path):
    """Read file safely with utf-8 fallback."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return ""


def normalize_php(code):
    """Very basic normalization: remove comments and collapse whitespace."""
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)  # remove /* */ comments
    code = re.sub(r"//.*", "", code)  # remove //
    code = re.sub(r"#.*", "", code)   # remove #
    code = re.sub(r"\s+", " ", code)  # collapse whitespace
    return code.strip()


def predict_file(model, vectorizer, php_path):
    """Predict safety of one PHP file."""
    code = read_file(php_path)
    norm_code = normalize_php(code)
    X = vectorizer.transform([norm_code])
    prob = model.predict_proba(X)[0][1]
    label = "unsafe" if prob >= 0.533 else "safe"
    return php_path, label, prob


def main():
    parser = argparse.ArgumentParser(description="Predict PHP vulnerability (SQL injection).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Path to a single PHP file")
    group.add_argument("--dir", type=str, help="Path to a folder of PHP files")

    parser.add_argument("--model", type=str, required=True, help="Path to trained model .pkl file")
    parser.add_argument("--vectorizer", type=str, required=True, help="Path to TF-IDF vectorizer .pkl file")
    parser.add_argument("--out", type=str, default=None, help="Optional: save results to CSV")

    args = parser.parse_args()

    # Load model + vectorizer
    with open(args.model, "rb") as f:
        model = pickle.load(f)
    with open(args.vectorizer, "rb") as f:
        vectorizer = pickle.load(f)

    # Collect files
    php_files = []
    if args.file:
        php_files = [Path(args.file)]
    else:
        php_files = list(Path(args.dir).rglob("*.php"))

    if not php_files:
        print("No PHP files found.")
        return

    results = []
    for file in tqdm(php_files, desc="Scanning"):
        path, label, prob = predict_file(model, vectorizer, file)
        results.append((str(path), label, prob))

    print("\nResults:")
    for path, label, prob in results:
        print(f"{path} → {label.upper()} (prob_unsafe={prob:.2f})")

    if args.out:
        import csv
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "label", "prob_unsafe"])
            writer.writerows(results)
        print(f"\nSaved results to {args.out}")


if __name__ == "__main__":
    main()
