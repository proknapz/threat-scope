#!/usr/bin/env python3
"""
predict.py

Run inference with a saved vectorizer + model against one PHP file or a folder.

Usage examples:

# Single file
python scripts/predict.py --file path/to/example.php \
    --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl

# Folder (recursive)
python scripts/predict.py --dir data/to/scan --out_dir results/predictions \
    --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl

# With localization (sliding window)
python scripts/predict.py --file path/to/example.php --localize --window 6

Notes:
- The script uses the same simple normalization as preprocess.py (strips comments, collapses whitespace).
- Model and vectorizer are Pickle files produced by train.py
"""
import argparse
from pathlib import Path
import pickle
import re
from tqdm import tqdm
import csv
import sys

# -----------------------
# Helpers (same normalization as preprocess.py)
# -----------------------
def read_file_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        print(f"Failed to read {path}: {e}", file=sys.stderr)
        return ""

def normalize_php_code(code: str) -> str:
    # Remove /* ... */ block comments
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # Remove // comments
    code = re.sub(r"//.*", "", code)
    # Remove # comments
    code = re.sub(r"#.*", "", code)
    # Collapse whitespace
    code = re.sub(r"\s+", " ", code)
    return code.strip()

# sliding-window localization
def sliding_windows_lines(code: str, window: int = 5):
    lines = code.splitlines()
    if not lines:
        return [(1, 1, code)]
    windows = []
    n = len(lines)
    if n <= window:
        windows.append((1, n, "\n".join(lines)))
        return windows
    for i in range(0, n - window + 1):
        s = i + 1
        e = i + window
        snippet = "\n".join(lines[i:i + window])
        windows.append((s, e, snippet))
    return windows

# predict a single file (and optionally localize)
def predict_file(path: Path, vectorizer, model, localize=False, window=5):
    raw = read_file_text(path)
    norm = normalize_php_code(raw)
    X = vectorizer.transform([norm])
    prob = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else None
    pred = int(model.predict(X)[0])
    result = {
        "path": str(path),
        "prediction": "unsafe" if pred == 1 else "safe",
        "prob_unsafe": prob
    }
    if localize:
        # score every window and return top windows
        wins = sliding_windows_lines(raw, window=window)
        norms = [normalize_php_code(w[2]) for w in wins]
        Xw = vectorizer.transform(norms)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(Xw)[:,1]
        else:
            # fallback: use decision_function if available
            try:
                scores = model.decision_function(Xw)
                # map to 0-1 via simple logistic-like transform
                import numpy as np
                probs = 1/(1 + np.exp(-scores))
            except Exception:
                probs = [None]*len(wins)
        scored = []
        for (s,e,_), p in zip(wins, probs):
            scored.append((s,e, float(p) if p is not None else None))
        # sort by probability descending and take top 5
        scored_sorted = sorted(scored, key=lambda x: (x[2] is not None, x[2]), reverse=True)[:10]
        result['localization'] = scored_sorted
    return result

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Predict safe/unsafe for PHP file(s) using saved model")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Single PHP file to scan")
    group.add_argument("--dir", type=str, help="Directory to scan recursively for .php files")
    p.add_argument("--model", type=str, default="models/logreg_model.pkl", help="Path to saved model (pickle)")
    p.add_argument("--vectorizer", type=str, default="models/tfidf_vectorizer.pkl", help="Path to saved vectorizer (pickle)")
    p.add_argument("--out_dir", type=str, default=None, help="Directory to save predictions CSV and optional localization JSONs")
    p.add_argument("--localize", action="store_true", help="Run sliding-window localization and include top windows")
    p.add_argument("--window", type=int, default=5, help="Number of lines per sliding window when localizing")
    p.add_argument("--topk", type=int, default=20, help="How many top windows to include in localization output")
    return p.parse_args()

def main():
    args = parse_args()

    model_path = Path(args.model)
    vect_path = Path(args.vectorizer)
    if not model_path.exists() or not vect_path.exists():
        print(f"Model or vectorizer not found: {model_path}, {vect_path}", file=sys.stderr)
        sys.exit(2)

    with open(vect_path, "rb") as f:
        vectorizer = pickle.load(f)
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    # collect files
    files = []
    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"File not found: {p}", file=sys.stderr)
            sys.exit(2)
        files = [p]
    else:
        d = Path(args.dir)
        if not d.exists():
            print(f"Directory not found: {d}", file=sys.stderr)
            sys.exit(2)
        files = sorted([p for p in d.rglob("*.php") if p.is_file()])

    if not files:
        print("No .php files found to scan.", file=sys.stderr)
        sys.exit(0)

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for f in tqdm(files, desc="Predicting", unit="file"):
        res = predict_file(f, vectorizer, model, localize=args.localize, window=args.window)
        results.append(res)

    # Print summary table (CSV-like)
    print("\nPredictions:")
    print("path, prediction, prob_unsafe")
    for r in results:
        print(f"{r['path']}, {r['prediction']}, {r['prob_unsafe']}")

    # Save CSV if requested
    if out_dir:
        csv_path = out_dir / "predictions.csv"
        with open(csv_path, "w", newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(["path","prediction","prob_unsafe"])
            for r in results:
                writer.writerow([r['path'], r['prediction'], r['prob_unsafe']])
        print(f"\nWrote predictions CSV to: {csv_path}")

        # write localization JSONs if requested
        if args.localize:
            import json
            for r in results:
                if 'localization' in r and r['localization']:
                    name = Path(r['path']).stem + "_localization.json"
                    with open(out_dir / name, "w", encoding='utf-8') as jf:
                        json.dump({
                            "path": r['path'],
                            "prediction": r['prediction'],
                            "prob_unsafe": r['prob_unsafe'],
                            "top_windows": r['localization'][:args.topk]
                        }, jf, indent=2)
            print(f"Wrote localization JSONs to: {out_dir}")

if __name__ == "__main__":
    main()
