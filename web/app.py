from flask import Flask, request, render_template, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import os
import pickle
from werkzeug.utils import secure_filename
import sys
from scripts.detect_lines import predict_file, apply_fixes, read_file
from code_mitigator import create_mitigator
from fix_validator import validate_fixes
import pandas as pd
from io import StringIO
import csv
import re

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"php"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = 'your-secret-key-here'  # For flash messages
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database configuration - try MySQL first, fallback to SQLite
database_url = os.environ.get('DATABASE_URL', 'sqlite:///scans.db')
if database_url.startswith('mysql'):
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text)
    fixes = db.Column(db.Text)  # Store generated fixes as JSON
    total_lines = db.Column(db.Integer, default=0)
    unsafe_lines = db.Column(db.Integer, default=0)
    safe_lines = db.Column(db.Integer, default=0)
    file_size = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'timestamp': self.timestamp.isoformat(),
            'total_lines': self.total_lines,
            'unsafe_lines': self.unsafe_lines,
            'safe_lines': self.safe_lines,
            'file_size': self.file_size,
            'vulnerability_rate': round((self.unsafe_lines / self.total_lines * 100), 2) if self.total_lines > 0 else 0
        }

# Wait for database to be ready
import time
import sys

def wait_for_db():
    """Wait for database to be ready with retries"""
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            with app.app_context():
                db.create_all()
            print("✅ Database connection successful")
            return True
        except Exception as e:
            retry_count += 1
            print(f"⏳ Waiting for database... (attempt {retry_count}/{max_retries})")
            time.sleep(2)
    
    print("❌ Failed to connect to database after 30 attempts")
    return False

# Only try to create tables if we can connect
if wait_for_db():
    print("🚀 Database ready, starting application...")
else:
    print("⚠️ Database not ready, but continuing with SQLite fallback...")
    # Fallback to SQLite if MySQL fails
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
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
    original_code = None
    fixed_code = None
    fixes_applied = None
    fixed_line_nums = None

    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            
            # Read original code
            original_code = read_file(filepath)
            original_lines = original_code.splitlines()
            
            # Run detection
            raw_results = predict_file(model, vectorizer, filepath, threshold=0.7)
            
            # Apply fixes
            original_lines = original_code.splitlines()
            fixed_lines, fixes_applied, fixed_line_nums = apply_fixes(original_lines, raw_results)
            fixed_code = '\n'.join(fixed_lines)
            
            # Debug: Log fixed line numbers and fixes
            app.logger.warning(f"🔧 Fixed line numbers: {sorted(fixed_line_nums)}")
            for line_num, original, fixed, params in fixes_applied:
                fix_lines = fixed.count('\n') + 1
                app.logger.warning(f"   Line {line_num}: {fix_lines} line(s) - {fixed[:50]}...")
            
            # Prepare results for template
            results = []
            unsafe_count = 0
            safe_count = 0
            for idx, line, label, prob, reports in raw_results:
                results.append({
                    "line_num": idx,
                    "line": line.rstrip(),
                    "label": label,
                    "prob": f"{prob:.3f}",
                    "reports": reports
                })
                if label == "unsafe":
                    unsafe_count += 1
                else:
                    safe_count += 1

            # Get file size
            file_size = os.path.getsize(filepath)

            # Convert fixes_applied to the modal format
            fix_report = {
                'summary': {
                    'total_vulnerabilities': unsafe_count,
                    'fixes_generated': len(fixes_applied) if fixes_applied else 0
                },
                'fixes': []
            }
            
            if fixes_applied:
                for line_num, original, fixed, params in fixes_applied:
                    # Determine fix type based on the code
                    if 'mysql_query' in original:
                        fix_type = 'SQL Injection - Deprecated Function'
                        explanation = 'Replaced deprecated mysql_query with prepared statement using mysqli. The mysql_query() function is deprecated and vulnerable to SQL injection. Prepared statements separate SQL code from data, preventing injection attacks by treating user input as data only, never as executable code. This approach is more secure and also provides better performance through query plan caching.'
                    elif re.search(r'\$\w+\s*=\s*["\'][^"\']*\$\w+[^"\']*["\']', original):
                        fix_type = 'SQL Injection - Variable Interpolation'
                        interpolated_vars = re.findall(r'\$(\w+)', original)
                        var_list = ", ".join([f"${v}" for v in interpolated_vars if v not in ['query', 'sql', 'stmt', 'result']])
                        explanation = f'Variable interpolation in SQL queries is dangerous. The original code embedded {var_list} directly in the SQL string, which allows attackers to inject malicious SQL. Use prepared statements with parameter binding (? placeholders) instead of embedding variables directly in SQL strings.'
                    else:
                        fix_type = 'SQL Injection - Direct Concatenation'
                        # Extract concatenated variables
                        concat_vars = re.findall(r'\.\s*\$(\w+)', original)
                        var_list = ", ".join([f"${v}" for v in concat_vars])
                        explanation = f'Replaced direct string concatenation with prepared statements to prevent SQL injection. The original code concatenated {var_list} directly into the SQL query, which allows attackers to inject malicious SQL. The fix uses parameterized queries with ? placeholders where user input is treated as data only.'
                    
                    fix_report['fixes'].append({
                        'line': line_num,
                        'type': fix_type,
                        'original': original,
                        'fixed': fixed,
                        'explanation': explanation
                    })

            # Save scan to database with statistics and fixes
            scan_entry = Scan(
                filename=filename,
                results=json.dumps(results),
                fixes=json.dumps(fix_report),  # Store the complete fix report
                total_lines=len(raw_results),
                unsafe_lines=unsafe_count,
                safe_lines=safe_count,
                file_size=file_size
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
        past_scans=past_scans,
        original_code=original_code,
        fixed_code=fixed_code,
        fixes_applied=fixes_applied,
        fixed_line_nums=list(fixed_line_nums) if fixed_line_nums else []
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

@app.route("/scans")
def past_scans_page():
    """Past scans page"""
    past_scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return render_template("scans.html", past_scans=past_scans)

@app.route("/database")
def database_management():
    """Database management interface"""
    # Get statistics
    total_scans = Scan.query.count()
    total_files = db.session.query(db.func.count(db.func.distinct(Scan.filename))).scalar()
    total_unsafe_lines = db.session.query(db.func.sum(Scan.unsafe_lines)).scalar() or 0
    total_safe_lines = db.session.query(db.func.sum(Scan.safe_lines)).scalar() or 0
    
    # Recent scans
    recent_scans = Scan.query.order_by(Scan.timestamp.desc()).limit(10).all()
    
    # File statistics
    file_stats_raw = db.session.query(
        Scan.filename,
        db.func.count(Scan.id).label('scan_count'),
        db.func.avg(Scan.unsafe_lines).label('avg_unsafe'),
        db.func.max(Scan.timestamp).label('last_scanned')
    ).group_by(Scan.filename).order_by(db.func.count(Scan.id).desc()).all()
    
    # Convert Row objects to dictionaries for JSON serialization
    file_stats = []
    for row in file_stats_raw:
        file_stats.append({
            'filename': row.filename,
            'scan_count': row.scan_count,
            'avg_unsafe': float(row.avg_unsafe) if row.avg_unsafe else 0.0,
            'last_scanned': row.last_scanned.isoformat() if row.last_scanned else None
        })
    
    return render_template("database.html", 
                         total_scans=total_scans,
                         total_files=total_files,
                         total_unsafe_lines=total_unsafe_lines,
                         total_safe_lines=total_safe_lines,
                         recent_scans=recent_scans,
                         file_stats=file_stats)

@app.route("/api/scans")
def api_scans():
    """API endpoint for scan data"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    scans = Scan.query.order_by(Scan.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'scans': [scan.to_dict() for scan in scans.items],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page
    })

@app.route("/api/export/csv")
def export_csv():
    """Export scan data as CSV"""
    scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Filename', 'Timestamp', 'Total Lines', 'Unsafe Lines', 'Safe Lines', 'File Size', 'Vulnerability Rate'])
    
    # Write data
    for scan in scans:
        vulnerability_rate = round((scan.unsafe_lines / scan.total_lines * 100), 2) if scan.total_lines > 0 else 0
        writer.writerow([
            scan.id,
            scan.filename,
            scan.timestamp.isoformat(),
            scan.total_lines,
            scan.unsafe_lines,
            scan.safe_lines,
            scan.file_size,
            f"{vulnerability_rate}%"
        ])
    
    output.seek(0)
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": "attachment; filename=scan_results.csv"}
    )

@app.route("/api/scan/<int:scan_id>/delete", methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan"""
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan deleted successfully'})

@app.route("/api/scans/delete-all", methods=['DELETE'])
def delete_all_scans():
    """Delete all scans from the database"""
    try:
        deleted_count = Scan.query.count()
        Scan.query.delete()
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'All scans deleted successfully',
            'deleted_count': deleted_count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/stats")
def api_stats():
    """API endpoint for comprehensive statistics"""
    from datetime import datetime, timedelta
    
    total_scans = Scan.query.count()
    total_files = db.session.query(db.func.count(db.func.distinct(Scan.filename))).scalar()
    total_unsafe_lines = db.session.query(db.func.sum(Scan.unsafe_lines)).scalar() or 0
    total_safe_lines = db.session.query(db.func.sum(Scan.safe_lines)).scalar() or 0
    total_lines = total_unsafe_lines + total_safe_lines
    
    # Calculate overall vulnerability rate
    overall_vuln_rate = (total_unsafe_lines / total_lines * 100) if total_lines > 0 else 0
    
    # Vulnerability rate over time (last 30 days) - grouped by day
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_scans = Scan.query.filter(Scan.timestamp >= thirty_days_ago).all()
    
    # Group by date and calculate daily averages
    daily_data = {}
    for scan in recent_scans:
        date_key = scan.timestamp.date().isoformat()
        if date_key not in daily_data:
            daily_data[date_key] = {'total_unsafe': 0, 'total_lines': 0, 'scan_count': 0}
        
        daily_data[date_key]['total_unsafe'] += scan.unsafe_lines or 0
        daily_data[date_key]['total_lines'] += scan.total_lines or 0
        daily_data[date_key]['scan_count'] += 1
    
    vulnerability_trend = []
    for date, data in sorted(daily_data.items()):
        rate = (data['total_unsafe'] / data['total_lines'] * 100) if data['total_lines'] > 0 else 0
        vulnerability_trend.append({
            'date': date,
            'rate': round(rate, 2),
            'scans': data['scan_count'],
            'unsafe_lines': data['total_unsafe'],
            'total_lines': data['total_lines']
        })
    
    # Most scanned files (top 10)
    most_scanned_raw = db.session.query(
        Scan.filename,
        db.func.count(Scan.id).label('scan_count'),
        db.func.avg(Scan.unsafe_lines).label('avg_unsafe'),
        db.func.max(Scan.timestamp).label('last_scanned')
    ).group_by(Scan.filename).order_by(db.func.count(Scan.id).desc()).limit(10).all()
    
    most_scanned_files = []
    for row in most_scanned_raw:
        most_scanned_files.append({
            'filename': row.filename,
            'scan_count': row.scan_count,
            'avg_unsafe': round(float(row.avg_unsafe) if row.avg_unsafe else 0, 1),
            'last_scanned': row.last_scanned.isoformat() if row.last_scanned else None
        })
    
    # Risk distribution
    all_scans = Scan.query.all()
    risk_distribution = {'high_risk': 0, 'medium_risk': 0, 'low_risk': 0, 'safe': 0}
    
    for scan in all_scans:
        if scan.total_lines > 0:
            vuln_rate = scan.unsafe_lines / scan.total_lines
            if vuln_rate > 0.1:
                risk_distribution['high_risk'] += 1
            elif vuln_rate > 0.05:
                risk_distribution['medium_risk'] += 1
            elif vuln_rate > 0:
                risk_distribution['low_risk'] += 1
            else:
                risk_distribution['safe'] += 1
        else:
            risk_distribution['safe'] += 1
    
    # Recent activity (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_activity_scans = Scan.query.filter(Scan.timestamp >= seven_days_ago).all()
    
    activity_by_date = {}
    for scan in recent_activity_scans:
        date_key = scan.timestamp.date().isoformat()
        activity_by_date[date_key] = activity_by_date.get(date_key, 0) + 1
    
    recent_activity = [{'date': date, 'scans': count} for date, count in sorted(activity_by_date.items())]
    
    # File size statistics
    file_sizes = [scan.file_size for scan in all_scans if scan.file_size]
    file_size_stats = {
        'avg_size': round(sum(file_sizes) / len(file_sizes), 2) if file_sizes else 0,
        'min_size': min(file_sizes) if file_sizes else 0,
        'max_size': max(file_sizes) if file_sizes else 0
    }
    
    return jsonify({
        'total_scans': total_scans,
        'total_files': total_files,
        'total_unsafe_lines': total_unsafe_lines,
        'total_safe_lines': total_safe_lines,
        'overall_vulnerability_rate': round(overall_vuln_rate, 2),
        'vulnerability_trend': vulnerability_trend,
        'most_scanned_files': most_scanned_files,
        'risk_distribution': risk_distribution,
        'recent_activity': recent_activity,
        'file_size_stats': file_size_stats,
        
        # Additional security metrics
        'security_metrics': {
            'detection_rate': round(overall_vuln_rate, 2),  # Same as vulnerability rate
            'false_positive_estimate': 22.8,  # Based on our model's FPR
            'model_confidence': 95.6,  # Based on our recall rate
            'coverage_score': min(100, round((total_scans / max(total_files, 1)) * 20, 1)),  # Normalize to 0-100% scale
            'threat_level': 'Medium' if overall_vuln_rate > 10 else 'Low' if overall_vuln_rate > 5 else 'Minimal',
            'scan_frequency': round(total_scans / max(total_files, 1), 1),  # Average scans per file
            'high_risk_files': risk_distribution['high_risk'],
            'total_lines_analyzed': total_unsafe_lines + total_safe_lines
        },
        
        # Model performance metrics
        'model_performance': {
            'precision': 39.8,  # From our evaluation
            'recall': 95.6,     # From our evaluation  
            'f1_score': 56.2,   # From our evaluation
            'threshold': 0.719, # Optimal threshold
            'accuracy': 77.2,   # From our evaluation
            'specificity': 77.2 # True negative rate
        }
    })

@app.route('/api/scan/<int:scan_id>/mitigate', methods=['GET'])
def mitigate_vulnerabilities(scan_id):
    """Retrieve stored mitigation suggestions for a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # Retrieve stored fixes instead of regenerating
        if scan.fixes:
            report = json.loads(scan.fixes)
            app.logger.warning(f"✅ Retrieved stored fixes for scan #{scan_id}")
        else:
            # Fallback: generate fixes if not stored (for old scans)
            app.logger.warning(f"⚠️  No stored fixes found for scan #{scan_id}, generating...")
            scan_results = json.loads(scan.results)
            mitigator = create_mitigator()
            fixes = mitigator.analyze_and_fix_vulnerabilities(scan_results)
            report = mitigator.generate_fix_report(fixes, scan.filename)
            
            # Store for future use
            scan.fixes = json.dumps(report)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'filename': scan.filename,
            'report': report
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/mitigate', methods=['POST'])
def mitigate_code():
    """Generate mitigation suggestions for uploaded code"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename.lower().endswith('.php'):
            # Save uploaded file temporarily
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            try:
                # Scan for vulnerabilities
                results = predict_file(model, vectorizer, filepath)
                
                # Generate mitigation suggestions
                mitigator = create_mitigator()
                fixes = mitigator.analyze_and_fix_vulnerabilities(results)
                report = mitigator.generate_fix_report(fixes, filename)
                
                # Clean up temporary file
                os.remove(filepath)
                
                return jsonify({
                    'success': True,
                    'filename': filename,
                    'scan_results': len(results),
                    'vulnerabilities_found': len([r for r in results if (isinstance(r, dict) and r.get('label') == 'unsafe') or (isinstance(r, tuple) and len(r) >= 3 and r[2] == 'unsafe')]),
                    'fixes_generated': len(fixes),
                    'report': report
                })
                
            except Exception as e:
                # Clean up on error
                if os.path.exists(filepath):
                    os.remove(filepath)
                raise e
        
        return jsonify({'error': 'Invalid file type. Please upload a PHP file.'}), 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
