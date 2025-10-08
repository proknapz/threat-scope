import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

df = pd.read_csv("results/predictions.csv")

# assuming unsafe=1, safe=0
df["true_label"] = df["path"].apply(lambda p: 1 if "unsafe" in p else 0)
df["pred_label"] = df["label"].map({"unsafe": 1, "safe": 0})

print(confusion_matrix(df["true_label"], df["pred_label"]))
print(classification_report(df["true_label"], df["pred_label"], digits=4))
