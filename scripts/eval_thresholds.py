import pickle
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import pandas as pd

# --- Load model and vectorizer ---
with open("models/logreg_model.pkl", "rb") as f:
    model = pickle.load(f)
with open("models/tfidf_vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# --- Load preprocessed data ---
df = pd.read_csv("preprocessed/train_processed.csv")
X_train, X_val, y_train, y_val = train_test_split(
    df['code'], df['label'], test_size=0.15, random_state=42, stratify=df['label']
)

# --- Transform validation data ---
X_val_vect = vectorizer.transform(X_val)
probs = model.predict_proba(X_val_vect)[:, 1]  # probability of unsafe

# --- Sweep thresholds ---
thresholds = np.linspace(0, 1, 200)
precision_list, recall_list, f1_list = [], [], []
target_recall = 0.95
best_threshold = 0
best_metrics = {"precision": 0, "recall": 0, "f1": 0}

for t in thresholds:
    preds = (probs >= t).astype(int)
    precision = precision_score(y_val, preds)
    recall = recall_score(y_val, preds)
    f1 = f1_score(y_val, preds)

    precision_list.append(precision)
    recall_list.append(recall)
    f1_list.append(f1)

    # Check target recall for recommended threshold
    if recall >= target_recall and f1 > best_metrics["f1"]:
        best_threshold = t
        best_metrics = {"precision": precision, "recall": recall, "f1": f1}

print(f"Recommended threshold for recall >= {target_recall}: {best_threshold:.3f}")
print(best_metrics)

# --- Plot the graph ---
plt.figure(figsize=(8,5))
plt.plot(thresholds, precision_list, label="Precision", color="blue")
plt.plot(thresholds, recall_list, label="Recall", color="green")
plt.plot(thresholds, f1_list, label="F1-score", color="red")
plt.axvline(best_threshold, color="purple", linestyle="--", label=f"Recommended Threshold {best_threshold:.3f}")
plt.xlabel("Threshold")
plt.ylabel("Score")
plt.title("Precision / Recall / F1 vs Threshold")
plt.legend()
plt.grid(True)
plt.show()
