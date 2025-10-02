#!/usr/bin/env python3
"""
train.py

Train a Logistic Regression classifier on preprocessed PHP code.

Usage:
  python train.py --input preprocessed/train_processed.csv --model_out models/logreg_model.pkl --vectorizer_out models/tfidf_vectorizer.pkl
"""

import pandas as pd
import argparse
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import pickle
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Train ML classifier on PHP code")
    parser.add_argument("--input", required=True, help="Preprocessed CSV with code and labels")
    parser.add_argument("--model_out", required=True, help="Path to save trained model")
    parser.add_argument("--vectorizer_out", required=True, help="Path to save TF-IDF vectorizer")
    args = parser.parse_args()

    # Load CSV
    df = pd.read_csv(args.input)
    print(f"Loaded {len(df)} samples.")

    # Split into train/validation
    X_train, X_val, y_train, y_val = train_test_split(
        df['code'], df['label'], test_size=0.15, random_state=42, stratify=df['label']
    )
    print(f"Training samples: {len(X_train)}, Validation samples: {len(X_val)}")

    # Vectorize code using TF-IDF
    vectorizer = TfidfVectorizer(
        analyzer='char_wb',  # character n-grams
        ngram_range=(3,5),   # 3-5 character n-grams
        max_features=5000
    )
    X_train_vect = vectorizer.fit_transform(X_train)
    X_val_vect = vectorizer.transform(X_val)

    # Train Logistic Regression
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(X_train_vect, y_train)

    # Evaluate
    y_pred = clf.predict(X_val_vect)
    print("\nValidation Results:")
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

    print(f"\nModel saved to: {model_path}")
    print(f"Vectorizer saved to: {vectorizer_path}")

if __name__ == "__main__":
    main()
