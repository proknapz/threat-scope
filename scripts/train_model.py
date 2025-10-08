#!/usr/bin/env python3
"""
train_model.py

Train a Logistic Regression classifier on PHP code samples located in:
  train/safe/
  train/unsafe/

Usage (Windows):
  python scripts/train_model.py --input_dir data/train --model_out models/logreg_model.pkl --vectorizer_out models/tfidf_vectorizer.pkl
"""

import os
import pandas as pd
import argparse
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from pathlib import Path
import pickle
from tqdm import tqdm  # ✅ NEW: for progress bars

def read_file_content(filepath):
    """Read the contents of a code file safely."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}")
        return ""

def load_dataset(input_dir):
    """Walk through train/safe and train/unsafe folders and build a labeled dataset."""
    data = []
    input_dir = Path(input_dir)

    for label_name, label in [("safe", 0), ("unsafe", 1)]:
        folder = input_dir / label_name
        if not folder.exists():
            print(f"[WARN] Folder not found: {folder}")
            continue

        files = [os.path.join(root, file)
                 for root, _, filenames in os.walk(folder)
                 for file in filenames if file.endswith(".php")]

        print(f"\n📂 Loading {label_name} files ({len(files)} found)...")

        # ✅ Add a progress bar when reading files
        for path in tqdm(files, desc=f"Reading {label_name}", ncols=80):
            code = read_file_content(path)
            if code.strip():
                data.append({"filename": str(path), "code": code, "label": label})
    
    df = pd.DataFrame(data)
    print(f"\n✅ Loaded {len(df)} total samples from {input_dir}")
    return df

def main():
    parser = argparse.ArgumentParser(description="Train ML classifier on PHP code.")
    parser.add_argument("--input_dir", required=True, help="Directory containing 'safe' and 'unsafe' folders")
    parser.add_argument("--model_out", required=True, help="Path to save the trained model")
    parser.add_argument("--vectorizer_out", required=True, help="Path to save the TF-IDF vectorizer")
    args = parser.parse_args()

    # Load dataset
    df = load_dataset(args.input_dir)
    if df.empty:
        print("❌ No data found! Check your input directory.")
        return

    # Split data
    X_train, X_val, y_train, y_val = train_test_split(
        df["code"], df["label"], test_size=0.15, random_state=42, stratify=df["label"]
    )
    print(f"Training samples: {len(X_train)}, Validation samples: {len(X_val)}")

    # Vectorize code using TF-IDF with a progress bar
    print("\n🔠 Vectorizing text (this may take a while)...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=5000
    )
    with tqdm(total=2, desc="TF-IDF Progress", ncols=80) as pbar:
        X_train_vect = vectorizer.fit_transform(X_train)
        pbar.update(1)
        X_val_vect = vectorizer.transform(X_val)
        pbar.update(1)

    # Train Logistic Regression
    print("\n🤖 Training Logistic Regression model...")
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(X_train_vect, y_train)

    # Evaluate model
    y_pred = clf.predict(X_val_vect)
    print("\n📊 Validation Results:")
    print(f"Accuracy: {accuracy_score(y_val, y_pred):.4f}")
    print(classification_report(y_val, y_pred, digits=4))

    # Save model and vectorizer
    model_path = Path(args.model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)

    vectorizer_path = Path(args.vectorizer_out)
    vectorizer_path.parent.mkdir(parents=True, exist_ok=True)
    with open(vectorizer_path, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"\n✅ Model saved to: {model_path}")
    print(f"✅ Vectorizer saved to: {vectorizer_path}")

if __name__ == "__main__":
    main()
