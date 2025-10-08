import pickle
import numpy as np
import matplotlib.pyplot as plt

with open("models/logreg_model.pkl", "rb") as f:
    clf = pickle.load(f)

with open("models/tfidf_vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

feature_names = vectorizer.get_feature_names_out()
coefs = clf.coef_[0]

top_n = 20
top_indices = np.argsort(coefs)[-top_n:][::-1]
top_features = feature_names[top_indices]
top_values = coefs[top_indices]

bottom_indices = np.argsort(coefs)[:top_n]
bottom_features = feature_names[bottom_indices]
bottom_values = coefs[bottom_indices]

plt.figure(figsize=(12,8))
plt.barh(top_features[::-1], top_values[::-1], color='red', label='Unsafe')
plt.barh(bottom_features[::-1], bottom_values[::-1], color='green', label='Safe')
plt.xlabel("Coefficient Value")
plt.title("Top n-grams Influencing Logistic Regression Predictions")
plt.legend()
plt.tight_layout()
plt.show()
