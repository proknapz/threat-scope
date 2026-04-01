#!/usr/bin/env python3
"""
detect_lines.py

Detect potentially unsafe lines in PHP files using a trained ML model
and taint analysis.

Usage:
python scripts/detect_lines.py --file data/train/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-concatenation_simple_quote.php --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --threshold 0.7
python scripts/detect_lines.py --file data/train/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-email_filter__join-concatenation_simple_quote.php --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --threshold 0.7
"""

import argparse
import pickle
import re
from pathlib import Path
from tqdm import tqdm
import numpy as np

# -----------------------------
# File reading and normalization
# -----------------------------
def read_file(file_path):
    try:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"Failed to read {file_path}: {e}")
        return ""

def normalize_php(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"\s+", " ", code)
    return code.strip()

# -----------------------------
# Simple taint analysis
# -----------------------------
# User-controlled superglobals: $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES,
# and dangerous $_SERVER keys that are populated from HTTP request headers or
# URL components and therefore user-controlled.
SUPERGLOBAL_PAT = re.compile(
    r'\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\['
    r'|\$_SERVER\s*\[\s*["\']'
    r'(?:HTTP_\w+|QUERY_STRING|PATH_INFO|PHP_SELF|REQUEST_URI|DOCUMENT_URI|ORIG_PATH_INFO|REMOTE_ADDR)',
    re.IGNORECASE,
)
ASSIGN_PAT = re.compile(r'\$([A-Za-z_]\w*)\s*=\s*(.+);')
CAST_PAT = re.compile(r'\(\s*(int|integer|float|double|real)\s*\)')
VAR_USAGE_PAT = re.compile(r'\$[A-Za-z_]\w*')
# SQL execution sinks: classic mysql_*, mysqli_*, PDO, and other DB drivers
SQL_USE_PAT = re.compile(
    r'\b(mysql_query|mysqli_query|pdo->query|->query|prepare|execute'
    r'|pg_query|pg_execute|mssql_query|sqlite_query|oci_execute|db2_exec|sqlsrv_query|sqlsrv_execute)\b'
    r'|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b',
    re.IGNORECASE,
)
# Command-execution sinks (CWE-78 — OS Command Injection)
CMD_SINK_PAT = re.compile(
    r'\b(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(',
    re.IGNORECASE,
)
# File-inclusion sinks (CWE-98 — PHP Remote/Local File Inclusion)
FILE_INCLUDE_PAT = re.compile(
    r'\b(include|require|include_once|require_once)\s*[\(\s]',
    re.IGNORECASE,
)

# -----------------------------
# Sanitizer regexes (split)
# -----------------------------
# SQL-safe sanitizers (clear SQL taint): includes both old mysql_* and modern equivalents,
# plus numeric-coercion functions that guarantee a safe integer/float value.
SQL_SANITIZERS = re.compile(
    r'\b(mysqli_real_escape_string|mysql_real_escape_string|PDO::quote|addslashes|intval|floatval|intdiv)\s*\(',
    re.IGNORECASE,
)
# HTML-only sanitizers (DO NOT clear SQL taint)
HTML_ONLY_SANITIZERS = re.compile(r'\b(filter_var|htmlspecialchars|htmlentities|FILTER_SANITIZE_FULL_SPECIAL_CHARS|FILTER_SANITIZE_STRING)\b', re.IGNORECASE)

def taint_analysis(lines):
    tainted = {}  # var -> bool
    line_reports = {}  # lineno -> list of (var, tainted, reason)

    for idx, line in enumerate(lines, start=1):
        code = line.strip()
        reports = []

        # Assignment detection
        m = ASSIGN_PAT.search(code)
        if m:
            var, rhs = m.group(1), m.group(2).strip()
            if SUPERGLOBAL_PAT.search(rhs):
                tainted[var] = True
                reports.append((var, True, "assigned from superglobal"))
            elif CAST_PAT.search(rhs) or SQL_SANITIZERS.search(rhs):
                # SQL-safe sanitizer or cast: clear taint
                tainted[var] = False
                reports.append((var, False, "sanitized/casted (SQL-safe)"))
            elif HTML_ONLY_SANITIZERS.search(rhs):
                # HTML-only sanitizer: do NOT clear SQL taint
                tainted[var] = True
                reports.append((var, True, "sanitized for HTML only — still tainted"))
            else:
                # propagate taint from used vars — if ANY used variable is tainted the
                # result is tainted (OR semantics prevents taint laundering via concatenation)
                used_vars = VAR_USAGE_PAT.findall(rhs)
                any_known = any(u.lstrip('$') in tainted for u in used_vars if u.lstrip('$'))
                if any_known:
                    any_tainted = any(tainted.get(u.lstrip('$'), False) for u in used_vars if u.lstrip('$'))
                    tainted[var] = any_tainted
                    if any_tainted:
                        tainted_src = next(u for u in used_vars if tainted.get(u.lstrip('$'), False))
                        reports.append((var, True, f"inherits taint from {tainted_src}"))
                    else:
                        reports.append((var, False, f"inherits from {used_vars[0]}"))
                else:
                    tainted.setdefault(var, False)

        # Check SQL/execution usage
        if SQL_USE_PAT.search(code):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name:
                    is_tainted = tainted.get(u_name, False)
                    if is_tainted:
                        reports.append((u_name, True, "used in SQL/exec while tainted"))
                    else:
                        reports.append((u_name, False, "used in SQL/exec"))

        # Check command injection sinks (CWE-78)
        if CMD_SINK_PAT.search(code):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name:
                    is_tainted = tainted.get(u_name, False)
                    if is_tainted:
                        reports.append((u_name, True, "used in command execution while tainted"))
                    else:
                        reports.append((u_name, False, "used in command execution"))

        # Check file inclusion sinks (CWE-98)
        if FILE_INCLUDE_PAT.search(code):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name:
                    is_tainted = tainted.get(u_name, False)
                    if is_tainted:
                        reports.append((u_name, True, "used in file inclusion while tainted"))
                    else:
                        reports.append((u_name, False, "used in file inclusion"))

        if reports:
            line_reports[idx] = reports

    return line_reports, tainted

# -----------------------------
# ML line prediction
# -----------------------------
def predict_file(model, vectorizer, php_path, threshold=0.5):
    code = read_file(php_path)
    lines = code.splitlines()
    norm_lines = [normalize_php(l) for l in lines]
    X = vectorizer.transform(norm_lines)
    probs = model.predict_proba(X)[:,1]

    # Taint analysis
    taint_reports, _ = taint_analysis(lines)

    results = []
    for idx, (line, prob) in enumerate(zip(lines, probs), start=1):
        reports = taint_reports.get(idx, [])
        tainted_in_sql = any(r[1] and "SQL" in r[2].upper() for r in reports)
        tainted_in_cmd = any(r[1] and "COMMAND EXECUTION" in r[2].upper() for r in reports)
        tainted_in_include = any(r[1] and "FILE INCLUSION" in r[2].upper() for r in reports)

        # New: detect pure constant assignments or resource assignments
        is_constant_assignment = re.match(
            r'\s*\$[A-Za-z_]\w*\s*=\s*(["\'].*["\']|\d+(\.\d+)?|true|false|null|\[.*\])\s*;', 
            line, re.IGNORECASE
        )
        is_resource_assignment = bool(re.search(r'\bfopen\s*\(', line))

        if tainted_in_sql or tainted_in_cmd or tainted_in_include:
            label = "unsafe"
        elif is_constant_assignment or is_resource_assignment:
            # Override ML if it's a safe assignment
            label = "safe"
        else:
            label = "unsafe" if prob >= threshold else "safe"

        results.append((idx, line, label, prob, reports))
    return results



def _is_comment_only(line, in_block):
    """Return (is_comment_only, new_in_block).

    Detect if the given line is comment-only. Maintains block-comment state
    across lines via the in_block boolean. Handles //, #, and /* ... */ blocks.
    If a block comment ends on the same line but code follows, the line is
    considered not comment-only.
    """
    s = line.lstrip()
    # If already inside a block comment
    if in_block:
        end_idx = s.find('*/')
        if end_idx == -1:
            return True, True
        # There is an end to the block on this line. Check if anything follows it.
        rest = s[end_idx+2:].strip()
        return (rest == ''), False

    # Not in a block comment
    if s.startswith('//') or s.startswith('#'):
        return True, False
    if s.startswith('/*'):
        end_idx = s.find('*/')
        if end_idx == -1:
            return True, True
        rest = s[end_idx+2:].strip()
        return (rest == ''), False

    return False, False

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Detect unsafe lines in PHP file")
    parser.add_argument("--file", type=str, required=True, help="PHP file to scan")
    parser.add_argument("--model", type=str, required=True, help="Trained model .pkl")
    parser.add_argument("--vectorizer", type=str, required=True, help="TF-IDF vectorizer .pkl")
    parser.add_argument("--threshold", type=float, default=0.5, help="ML probability threshold")
    args = parser.parse_args()

    # Load model + vectorizer
    with open(args.model, "rb") as f:
        model = pickle.load(f)
    with open(args.vectorizer, "rb") as f:
        vectorizer = pickle.load(f)

    results = predict_file(model, vectorizer, args.file, threshold=args.threshold)

    print(f"\n🔍 Scanning {args.file} (threshold={args.threshold})...\n")
    unsafe_count = 0
    in_block = False
    for idx, line, label, prob, reports in results:
        # Skip pure comment lines (respecting block comment state)
        is_comment, in_block = _is_comment_only(line, in_block)
        if is_comment:
            continue
        icon = "⚠️ " if label=="unsafe" else "✅"
        if label=="unsafe":
            unsafe_count += 1
        print(f"{icon} [Line {idx:3}] prob={prob:.3f} → {line.strip()}")
        for r in reports:
            print(f"    • {r[0]} tainted={r[1]} ({r[2]})")

    print(f"\n📊 Summary:\nTotal lines scanned: {len(results)}\nUnsafe lines found: {unsafe_count}")

if __name__ == "__main__":
    main()
