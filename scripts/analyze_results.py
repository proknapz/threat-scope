#!/usr/bin/env python3
"""
analyze_results.py
Visualize prediction results from predict.py — shows model confidence, threshold, and confusion matrix.
Usage:
python scripts/analyze_results.py --predictions results/predictions.csv --threshold 0.533
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Analyze model predictions")
    parser.add_argument("--predictions", type=str, required=True, help="Path to results CSV (from predict.py)")
    parser.add_argument("--truth", type=str, default=None, help="Optional: path to ground-truth CSV (with real labels)")
    parser.add_argument("--threshold", type=float, default=None, help="Optional: threshold used for unsafe classification")
    args = parser.parse_args()

    results = pd.read_csv(args.predictions)
    print(f"Loaded {len(results)} predictions.")

    if "label" not in results.columns or "prob_unsafe" not in results.columns:
        raise ValueError("CSV must include 'label' and 'prob_unsafe' columns.")

    # If you have real labels (for validation set)
    if args.truth:
        truth = pd.read_csv(args.truth)
        df = results.merge(truth, on="path", suffixes=("_pred", "_true"))
        y_true = (df["label_true"] == "unsafe").astype(int)
        y_pred = (df["label_pred"] == "unsafe").astype(int)

        print("\nClassification report:")
        print(classification_report(y_true, y_pred))

        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Safe", "Unsafe"], yticklabels=["Safe", "Unsafe"])
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.show()

    # Probability histogram
    plt.figure(figsize=(8, 5))

    if "taint_flag" in results.columns:
        # Separate histogram for taint vs non-taint
        sns.histplot(data=results, x="prob_unsafe", hue="taint_flag", bins=20, kde=True,
                     palette={True: "red", False: "green"}, alpha=0.6)
        plt.legend(title="Tainted")
    else:
        sns.histplot(results["prob_unsafe"], bins=20, kde=True, color="purple")

    # Threshold line
    if args.threshold:
        plt.axvline(x=args.threshold, color='red', linestyle='--', label=f'Threshold={args.threshold}')
        plt.legend()

    plt.title("Distribution of Model Confidence (Unsafe Probability)")
    plt.xlabel("Probability of Unsafe")
    plt.ylabel("Count")
    plt.show()


if __name__ == "__main__":
    main()
