import pickle
import numpy as np

# Load trained model and vectorizer
with open("models/logreg_model.pkl", "rb") as f:
    clf = pickle.load(f)

with open("models/tfidf_vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# Get feature names (n-grams)
feature_names = vectorizer.get_feature_names_out()

# Get model coefficients
coefs = clf.coef_[0]  # Logistic Regression has shape (1, n_features) for binary classification

# Sort features by coefficient magnitude (most positive = strongest unsafe indicators)
top_n = 20
top_indices = np.argsort(coefs)[-top_n:][::-1]  # descending order

print("Top {} n-grams indicating UNSAFE files:".format(top_n))
for i in top_indices:
    print(f"{feature_names[i]} → coefficient: {coefs[i]:.4f}")

# Optionally, see the strongest safe indicators (most negative coefficients)
bottom_indices = np.argsort(coefs)[:top_n]
print("\nTop {} n-grams indicating SAFE files:".format(top_n))
for i in bottom_indices:
    print(f"{feature_names[i]} → coefficient: {coefs[i]:.4f}")
