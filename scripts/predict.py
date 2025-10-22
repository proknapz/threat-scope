#!/usr/bin/env python3
"""
predict.py
Predict if a PHP file is safe or unsafe using a trained model + vectorizer.
Usage:
python scripts/predict.py --file data/train/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-email_filter__join-concatenation_simple_quote.php --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl
python scripts/predict.py --dir data/train --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --out results/predictions.csv

"""
#!/usr/bin/env python3
"""
predict.py
Predict if a PHP file is safe or unsafe using a trained model + vectorizer.
Outputs optional CSV including taint flag.
"""

import argparse
import pickle
from pathlib import Path
import re
from tqdm import tqdm
import pandas as pd

def read_file(path):
    """Read file safely with utf-8 fallback."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return ""

def normalize_php(code):
    """Basic normalization: remove comments and collapse whitespace."""
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"\s+", " ", code)
    return code.strip()

def is_tainted_line(code_line):
    """Simple taint check for demonstration: detect usage of $_GET, $_POST, $_REQUEST."""
    taint_patterns = [r"\$_GET", r"\$_POST", r"\$_REQUEST"]
    return any(re.search(p, code_line) for p in taint_patterns)

def predict_file(model, vectorizer, php_path, threshold):
    """Predict safety of one PHP file."""
    code = read_file(php_path)
    lines = code.splitlines()
    results = []

    for idx, line in enumerate(lines, start=1):
        norm_line = normalize_php(line)
        prob = model.predict_proba(vectorizer.transform([norm_line]))[0][1]
        label = "unsafe" if prob >= threshold else "safe"
        taint_flag = is_tainted_line(line)
        results.append({
            "path": str(php_path),
            "line_num": idx,
            "code_line": line.strip(),
            "prob_unsafe": prob,
            "label": label,
            "taint_flag": taint_flag
        })

    return results

def main():
    parser = argparse.ArgumentParser(description="Predict PHP vulnerability (SQL injection).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Path to a single PHP file")
    group.add_argument("--dir", type=str, help="Path to a folder of PHP files")

    parser.add_argument("--model", type=str, required=True, help="Path to trained model .pkl file")
    parser.add_argument("--vectorizer", type=str, required=True, help="Path to TF-IDF vectorizer .pkl file")
    parser.add_argument("--threshold", type=float, default=0.5, help="Probability threshold for unsafe")
    parser.add_argument("--out", type=str, default=None, help="Optional: save results to CSV")
    args = parser.parse_args()

    # Load model + vectorizer
    with open(args.model, "rb") as f:
        model = pickle.load(f)
    with open(args.vectorizer, "rb") as f:
        vectorizer = pickle.load(f)

    # Collect files
    php_files = [Path(args.file)] if args.file else list(Path(args.dir).rglob("*.php"))

    if not php_files:
        print("No PHP files found.")
        return

    all_results = []
    for file in tqdm(php_files, desc="Scanning"):
        all_results.extend(predict_file(model, vectorizer, file, args.threshold))

    # Display results
    for r in all_results:
        flag = "⚠️" if r["label"] == "unsafe" else "✅"
        print(f"{flag} [Line {r['line_num']:3}] prob={r['prob_unsafe']:.3f} → {r['code_line']}")

    # Save to CSV if requested
    if args.out:
        df_out = pd.DataFrame(all_results)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        df_out.to_csv(args.out, index=False)
        print(f"\nSaved results to {args.out}")

if __name__ == "__main__":
    main()
