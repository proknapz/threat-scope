from flask import Flask, request, render_template, redirect, url_for
import os
import pickle
from werkzeug.utils import secure_filename
import sys
from scripts.detect_lines import predict_file



UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"php"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load model & vectorizer
with open("models/logreg_model.pkl", "rb") as f:
    model = pickle.load(f)
with open("models/tfidf_vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            
            # Run detection
            results = predict_file(model, vectorizer, filepath, threshold=0.7)
            
            # Prepare results for rendering
            highlighted = []
            for idx, line, label, prob, reports in results:
                highlighted.append({
                    "line_num": idx,
                    "line": line.rstrip(),
                    "label": label,
                    "prob": f"{prob:.3f}",
                    "reports": reports
                })
            return render_template("results.html", results=highlighted, filename=filename)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
