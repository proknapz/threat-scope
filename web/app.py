from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text)

with app.app_context():
    db.create_all()
# Load model & vectorizer
with open("models/logreg_model.pkl", "rb") as f:
    model = pickle.load(f)
with open("models/tfidf_vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    filename = None

    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            
            # Run detection
            raw_results = predict_file(model, vectorizer, filepath, threshold=0.7)
            
            # Prepare results for template
            results = []
            for idx, line, label, prob, reports in raw_results:
                results.append({
                    "line_num": idx,
                    "line": line.rstrip(),
                    "label": label,
                    "prob": f"{prob:.3f}",
                    "reports": reports
                })

            # Save scan to database
            scan_entry = Scan(
                filename=filename,
                results=json.dumps(results)
            )
            db.session.add(scan_entry)
            db.session.commit()
    
    # Load past scans
    past_scans = Scan.query.order_by(Scan.timestamp.desc()).all()

    # Render template with results and past scans
    return render_template(
        "index.html",
        results=results,
        filename=filename,
        past_scans=past_scans
    )

@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    results = json.loads(scan.results)
    past_scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return render_template(
        "index.html",
        results=results,
        filename=scan.filename,
        past_scans=past_scans
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
