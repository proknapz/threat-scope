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
SUPERGLOBAL_PAT = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[', re.IGNORECASE)
ASSIGN_PAT = re.compile(r'\$([A-Za-z_]\w*)\s*=\s*(.+?)(;|$)')  # Allow assignment without semicolon (for if/else blocks)
ARRAY_ASSIGN_PAT = re.compile(r'\$([A-Za-z_]\w*)\s*\[\s*.*?\s*\]\s*=\s*(.+?)(;|$)')  # Array assignment
ARRAY_APPEND_PAT = re.compile(r'\$([A-Za-z_]\w*)\s*\[\s*\]\s*=\s*(.+?)(;|$)')  # Array append
ARRAY_ACCESS_PAT = re.compile(r'\$([A-Za-z_]\w*)\s*\[\s*[^\]]+\s*\]')  # Array element access
CAST_PAT = re.compile(r'\(\s*(int|integer|float|double|real)\s*\)')
VAR_USAGE_PAT = re.compile(r'\$[A-Za-z_]\w*')
SQL_USE_PAT = re.compile(r'\b(mysql_query|mysqli_query|pdo->query|->query|prepare|execute)\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b', re.IGNORECASE)
# Match unsafe string concatenation in queries - look for . $var . pattern after SQL keywords
# This pattern matches: $var = "SELECT..." . $var or $var = "SELECT..." . $var . "..."
UNSAFE_QUERY_CONSTRUCTION_PAT = re.compile(
    r'\$\w+\s*=\s*["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*["\']\s*\.\s*\$', 
    re.IGNORECASE
)
# Also match patterns where SQL keyword appears and then concatenation happens
UNSAFE_QUERY_CONCAT_PAT = re.compile(
    r'\$\w+\s*=\s*["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"\']*["\']\s*\.\s*\$\w+', 
    re.IGNORECASE
)
SAFE_SPRINTF_PAT = re.compile(r'sprintf\s*\([^)]*%[duf]', re.IGNORECASE)  # Safe numeric format specifiers
UNSAFE_SPRINTF_PAT = re.compile(r'sprintf\s*\([^)]*%[s]', re.IGNORECASE)  # Unsafe string format specifier
BACKTICK_EXEC_PAT = re.compile(r'`[^`]+`')  # Backtick command execution
CONSTANT_ASSIGN_PAT = re.compile(r'=\s*(["\'].*["\']|\d+(\.\d+)?|true|false|null|array\s*\(|\[\s*\])', re.IGNORECASE)  # Constant assignments

# -----------------------------
# Sanitizer regexes (split)
# -----------------------------
# SQL-safe sanitizers (clear SQL taint)
SQL_SANITIZERS = re.compile(r'\b(mysqli_real_escape_string|PDO::quote|addslashes)\s*\(', re.IGNORECASE)
# HTML-only sanitizers (DO NOT clear SQL taint)
HTML_ONLY_SANITIZERS = re.compile(r'\b(filter_var|htmlspecialchars|htmlentities|FILTER_SANITIZE_FULL_SPECIAL_CHARS|FILTER_SANITIZE_STRING)\b', re.IGNORECASE)

def taint_analysis(lines):
    tainted = {}  # var -> bool
    array_tainted = {}  # array_name -> bool (track if array contains tainted elements)
    line_reports = {}  # lineno -> list of (var, tainted, reason)

    for idx, line in enumerate(lines, start=1):
        code = line.strip()
        reports = []

        # Check for array append (e.g., $array[] = $_GET['x'])
        m_append = ARRAY_APPEND_PAT.search(code)
        if m_append:
            array_name, rhs = m_append.group(1), m_append.group(2).strip()
            if SUPERGLOBAL_PAT.search(rhs):
                array_tainted[array_name] = True
                reports.append((array_name, True, "array element assigned from superglobal"))
        
        # Check for array assignment (e.g., $array[1] = $_GET['x'])
        m_array = ARRAY_ASSIGN_PAT.search(code)
        if m_array:
            array_name, rhs = m_array.group(1), m_array.group(2).strip()
            if SUPERGLOBAL_PAT.search(rhs):
                array_tainted[array_name] = True
                reports.append((array_name, True, "array element assigned from superglobal"))

        # Assignment detection
        m = ASSIGN_PAT.search(code)
        if m:
            var, rhs = m.group(1), m.group(2).strip()
            
            # FIRST: Check for safe patterns that should NOT be flagged
            if SAFE_SPRINTF_PAT.search(rhs):
                # Safe sprintf with numeric formats (%u, %d, %f) - clear taint
                tainted[var] = False
                reports.append((var, False, "assigned via safe sprintf (numeric format)"))
            elif CAST_PAT.search(rhs) or SQL_SANITIZERS.search(rhs):
                # SQL-safe sanitizer or cast: clear taint
                tainted[var] = False
                reports.append((var, False, "sanitized/casted (SQL-safe)"))
            # Check for sprintf with %s - treat as safe if user wants (or you can make this conditional)
            elif re.search(r'sprintf\s*\([^)]*%s', rhs, re.IGNORECASE):
                # sprintf with %s - marking as safe per user requirement
                # If you want to flag this as unsafe, remove this elif block
                tainted[var] = False
                reports.append((var, False, "assigned via sprintf (treated as safe)"))
            # Check for SQL query with direct variable (no concatenation operator) - treat as potentially safe
            elif re.search(r'\b(SELECT|INSERT|UPDATE|DELETE)\b', rhs, re.IGNORECASE) and '$' in rhs:
                # Has SQL keyword and variable, but check if it's direct usage (not concatenated)
                # Pattern like: "SELECT ... WHERE id= $var" (no . operator)
                # BUT: Variable interpolation in double-quoted strings is UNSAFE
                # Pattern: "SELECT ... WHERE id=' $var '" - variable interpolation
                if re.search(r'["\']\s*\.\s*\$|\$\s*\.\s*["\']', rhs):
                    # Has concatenation - check for tainted variables
                    has_sql_keyword = True
                    has_concatenation = True
                    used_vars = VAR_USAGE_PAT.findall(rhs)
                    for u in used_vars:
                        u_name = u.lstrip('$')
                        if u_name and tainted.get(u_name, False):
                            # Mark query variable as tainted and report
                            tainted[var] = True
                            reports.append((u_name, True, "used in SQL query construction while tainted"))
                            break
                    # If no tainted vars found, still mark as potentially unsafe
                    if not any(tainted.get(u.lstrip('$'), False) for u in used_vars if u.lstrip('$')):
                        tainted[var] = True
                        reports.append((var, True, "SQL query construction detected"))
                elif re.search(r'["\'].*\$\w+.*["\']', rhs):
                    # Variable interpolation in double-quoted string - UNSAFE
                    used_vars = VAR_USAGE_PAT.findall(rhs)
                    for u in used_vars:
                        u_name = u.lstrip('$')
                        if u_name and tainted.get(u_name, False):
                            # Mark query variable as tainted and report
                            tainted[var] = True
                            reports.append((u_name, True, "used in SQL query via variable interpolation while tainted"))
                            break
                    # If variable is in string but not tainted yet, still mark as potentially unsafe
                    if used_vars and not any(tainted.get(u.lstrip('$'), False) for u in used_vars if u.lstrip('$')):
                        tainted[var] = True
                        reports.append((var, True, "SQL query with variable interpolation detected"))
                else:
                    # Direct variable usage in query string - treat as safe (might be parameterized or sanitized)
                    tainted[var] = False
                    reports.append((var, False, "SQL query with direct variable (treated as safe)"))
            # Check if this is a constant assignment (clears taint) - only if NO concatenation and NO SQL
            elif CONSTANT_ASSIGN_PAT.search(rhs) and not ('.' in rhs and '$' in rhs):
                tainted[var] = False
                reports.append((var, False, "assigned constant value"))
            elif SUPERGLOBAL_PAT.search(rhs):
                tainted[var] = True
                reports.append((var, True, "assigned from superglobal"))
            elif BACKTICK_EXEC_PAT.search(rhs):
                # Backtick execution is a tainted source
                tainted[var] = True
                reports.append((var, True, "assigned from command execution (backticks)"))
            elif HTML_ONLY_SANITIZERS.search(rhs):
                # HTML-only sanitizer: do NOT clear SQL taint
                tainted[var] = True
                reports.append((var, True, "sanitized for HTML only — still tainted"))
            else:
                # Check for array access (e.g., $var = $array[1])
                array_match = ARRAY_ACCESS_PAT.search(rhs)
                if array_match:
                    array_name = array_match.group(1)
                    if array_tainted.get(array_name, False):
                        tainted[var] = True
                        reports.append((var, True, f"assigned from tainted array {array_name}"))
                    else:
                        tainted.setdefault(var, False)
                else:
                    # propagate taint from used vars if present
                    used_vars = VAR_USAGE_PAT.findall(rhs)
                    inherited = None
                    for u in used_vars:
                        u_name = u.lstrip('$')
                        if u_name in tainted:
                            inherited = tainted[u_name]
                            break
                    if inherited is not None:
                        tainted[var] = inherited
                        reports.append((var, inherited, f"inherits from {used_vars[0]}"))
                    else:
                        tainted.setdefault(var, False)

        # Check for UNSAFE query construction with tainted variables
        # Check for sprintf with unsafe %s format
        if re.search(r'\$\w+\s*=\s*sprintf\s*\([^)]*%s', code, re.IGNORECASE):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name and tainted.get(u_name, False):
                    reports.append((u_name, True, "used in SQL query construction with sprintf %s while tainted"))
                    # Mark the query variable as tainted
                    query_match = re.search(r'\$(\w+)\s*=\s*sprintf', code, re.IGNORECASE)
                    if query_match:
                        query_var = query_match.group(1)
                        tainted[query_var] = True
        # Check for unsafe string concatenation in queries - PRIMARY DETECTION
        elif (UNSAFE_QUERY_CONSTRUCTION_PAT.search(code) or UNSAFE_QUERY_CONCAT_PAT.search(code)) and not SAFE_SPRINTF_PAT.search(code):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name and tainted.get(u_name, False):
                    reports.append((u_name, True, "used in SQL query construction while tainted"))
                    # Mark the query variable as tainted
                    query_match = re.search(r'\$(\w+)\s*=\s*["\']', code)
                    if query_match:
                        query_var = query_match.group(1)
                        tainted[query_var] = True
        # Check for variable interpolation in SQL query strings (e.g., "SELECT ... WHERE id=' $var '")
        elif re.search(r'\$\w+\s*=\s*["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\$\w+.*["\']', code, re.IGNORECASE):
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name and tainted.get(u_name, False):
                    reports.append((u_name, True, "used in SQL query via variable interpolation while tainted"))
                    # Mark the query variable as tainted
                    query_match = re.search(r'\$(\w+)\s*=\s*["\']', code)
                    if query_match:
                        query_var = query_match.group(1)
                        tainted[query_var] = True
        # Fallback: Check for any query construction with SQL keywords and concatenation
        elif re.search(r'\$\w+\s*=\s*["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b', code, re.IGNORECASE):
            # Look for variables used in the query string with concatenation
            used_vars = VAR_USAGE_PAT.findall(code)
            for u in used_vars:
                u_name = u.lstrip('$')
                if u_name and tainted.get(u_name, False):
                    # Check if variable is used in string concatenation (unsafe)
                    if re.search(r'["\']\s*\.\s*\$\w+|\$\w+\s*\.\s*["\']', code):
                        reports.append((u_name, True, "used in SQL query construction while tainted"))
                        query_match = re.search(r'\$(\w+)\s*=\s*["\']', code)
                        if query_match:
                            query_var = query_match.group(1)
                            tainted[query_var] = True

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
    in_block = False  # Track block comment state
    for idx, (line, prob) in enumerate(zip(lines, probs), start=1):
        # Check if this line is a comment
        is_comment, in_block = _is_comment_only(line, in_block)
        
        reports = taint_reports.get(idx, [])
        tainted_in_sql = any(r[1] and "SQL" in r[2].upper() for r in reports)

        # New: detect pure constant assignments or resource assignments
        is_constant_assignment = re.match(
            r'\s*\$[A-Za-z_]\w*\s*=\s*(["\'].*["\']|\d+(\.\d+)?|true|false|null|\[.*\])\s*;', 
            line, re.IGNORECASE
        )
        is_resource_assignment = 'proc_open' in line or 'fopen' in line

        if is_comment:
            # Comments are always safe
            label = "safe"
        elif tainted_in_sql:
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
# Code fixing functions
# -----------------------------
def fix_unsafe_query_concatenation(line):
    """
    Fix unsafe SQL query construction with string concatenation.
    Converts: $query = "SELECT ... WHERE id=". $tainted . "";
    To: $query = "SELECT ... WHERE id=?";
    Returns fixed line and list of parameters to bind
    """
    # Pattern: $var = "SELECT..." . $tainted . "..."
    pattern = r'(\$\w+)\s*=\s*(["\'])(.*?)\2\s*\.\s*(\$\w+)\s*\.\s*(["\'])(.*?)\5\s*;'
    match = re.search(pattern, line, re.IGNORECASE | re.DOTALL)
    
    if match:
        var, quote1, query_part1, tainted_var, quote2, query_part2 = match.groups()
        # Replace concatenated variable with placeholder
        fixed_query = f'{var} = {quote1}{query_part1}?{query_part2}{quote1};'
        return fixed_query, [tainted_var]
    
    # Pattern: $var = "SELECT..." . $tainted;
    pattern2 = r'(\$\w+)\s*=\s*(["\'])(.*?)\2\s*\.\s*(\$\w+)\s*;'
    match2 = re.search(pattern2, line, re.IGNORECASE | re.DOTALL)
    if match2:
        var, quote, query_part, tainted_var = match2.groups()
        fixed_query = f'{var} = {quote}{query_part}?{quote};'
        return fixed_query, [tainted_var]
    
    # Pattern: $var = $tainted . "SELECT...";
    pattern3 = r'(\$\w+)\s*=\s*(\$\w+)\s*\.\s*(["\'])(.*?)\3\s*;'
    match3 = re.search(pattern3, line, re.IGNORECASE | re.DOTALL)
    if match3:
        var, tainted_var, quote, query_part = match3.groups()
        fixed_query = f'{var} = {quote}?{query_part}{quote};'
        return fixed_query, [tainted_var]
    
    return None, []

def fix_sprintf_unsafe(line):
    """
    Fix unsafe sprintf with %s format.
    Converts: $query = sprintf("SELECT ... WHERE id='%s'", $tainted);
    To: $query = "SELECT ... WHERE id=?";
    """
    # Pattern: sprintf("SELECT...%s...", $var)
    pattern = r'(\$\w+)\s*=\s*sprintf\s*\(\s*(["\'])(.*?%s.*?)\2\s*,\s*(\$\w+)\s*\)'
    match = re.search(pattern, line, re.IGNORECASE | re.DOTALL)
    
    if match:
        var, quote, query_template, tainted_var = match.groups()
        # Replace %s with ?
        fixed_query = query_template.replace('%s', '?')
        return f'{var} = {quote}{fixed_query}{quote};', [tainted_var]
    
    return None, []

def fix_variable_interpolation_unsafe(line):
    """
    Fix unsafe SQL query construction with variable interpolation in double-quoted strings.
    Converts: $query = "SELECT ... WHERE id=' $tainted '";
    To: $query = "SELECT ... WHERE id='?'";
    Returns fixed line and list of parameters to bind
    """
    # Pattern: $var = "SELECT...WHERE id=' $tainted '"
    # Match SQL query with variable interpolation in double-quoted string
    pattern = r'(\$\w+)\s*=\s*"([^"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"]*)(\$\w+)([^"]*)"\s*;'
    match = re.search(pattern, line, re.IGNORECASE | re.DOTALL)
    
    if match:
        var, query_part1, sql_keyword, tainted_var, query_part2 = match.groups()
        # Replace the variable with placeholder
        # Need to preserve the quotes around the placeholder
        # Find where the variable appears and replace it with ?
        fixed_query = query_part1 + '?' + query_part2
        return f'{var} = "{fixed_query}";', [tainted_var]
    
    # Pattern: $var = "SELECT...WHERE id=' $tainted '"; (with single quotes around variable)
    pattern2 = r'(\$\w+)\s*=\s*"([^"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"]*)[\'"]\s*(\$\w+)\s*[\'"]([^"]*)"\s*;'
    match2 = re.search(pattern2, line, re.IGNORECASE | re.DOTALL)
    
    if match2:
        var, query_part1, sql_keyword, tainted_var, query_part2 = match2.groups()
        # Replace variable with placeholder, preserving quotes
        fixed_query = query_part1 + "'?'" + query_part2
        return f'{var} = "{fixed_query}";', [tainted_var]
    
    return None, []

def fix_mysql_query_unsafe(line, query_var, params):
    """
    Fix unsafe mysql_query usage by converting to prepared statements.
    Converts: $res = mysql_query($query);
    To: $stmt = $pdo->prepare($query); $stmt->execute([$params]);
    """
    # Pattern: $res = mysql_query($query);
    pattern = r'(\$\w+)\s*=\s*mysql_query\s*\(\s*(\$\w+)\s*\)'
    match = re.search(pattern, line, re.IGNORECASE)
    
    if match:
        result_var, query_var_in_line = match.groups()
        if query_var_in_line == query_var and params:
            # Generate prepared statement code
            params_str = ', '.join(params)
            fixed = f'$stmt = $pdo->prepare({query_var});\n$stmt->execute([{params_str}]);\n{result_var} = $stmt;'
            return fixed
        else:
            # Generate actual prepared statement code (not commented)
            # Try to find parameters from context or use the query variable
            if params:
                params_str = ', '.join(params)
                fixed = f'$stmt = $pdo->prepare({query_var_in_line});\n$stmt->execute([{params_str}]);\n{result_var} = $stmt;'
            else:
                # If no params found, still generate the prepared statement structure
                fixed = f'$stmt = $pdo->prepare({query_var_in_line});\n$stmt->execute([/* add parameters here */]);\n{result_var} = $stmt;'
            return fixed
    
    return None

def fix_unsafe_line(line, reports, context_lines=None):
    """
    Fix an unsafe line based on the taint analysis reports.
    Returns the fixed line(s) and parameters to bind, or None if no fix is available.
    """
    fixed_lines = []
    params = []
    
    # Check if this is an unsafe SQL query construction
    for report in reports:
        if report[1] and "SQL query" in report[2]:
            # Try to fix query concatenation
            fixed, line_params = fix_unsafe_query_concatenation(line)
            if fixed:
                fixed_lines.append(fixed)
                params.extend(line_params)
                break
            
            # Try to fix sprintf
            fixed, line_params = fix_sprintf_unsafe(line)
            if fixed:
                fixed_lines.append(fixed)
                params.extend(line_params)
                break
            
            # Try to fix variable interpolation
            fixed, line_params = fix_variable_interpolation_unsafe(line)
            if fixed:
                fixed_lines.append(fixed)
                params.extend(line_params)
                break
    
    return fixed_lines if fixed_lines else None, params

def apply_fixes(lines, results):
    """
    Apply fixes to unsafe lines and return the fixed code.
    """
    fixed_lines = lines.copy()
    fixes_applied = []
    fixed_line_nums = set()  # Track all line numbers that are part of fixes
    query_vars = {}  # Track query variables and their parameters
    
    for idx, line, label, prob, reports in results:
        if label == "unsafe" and reports:
            fixed, params = fix_unsafe_line(line, reports)
            if fixed:
                # Apply the first fix (most common case)
                fixed_lines[idx - 1] = fixed[0]  # idx is 1-based, list is 0-based
                fixes_applied.append((idx, line, fixed[0], params))
                fixed_line_nums.add(idx)  # Mark original line as fixed
                
                # If fix spans multiple lines, mark all new lines as fixed
                if '\n' in fixed[0]:
                    # Count how many lines the fix spans
                    fix_line_count = fixed[0].count('\n') + 1
                    for i in range(idx, idx + fix_line_count):
                        fixed_line_nums.add(i)
                
                # Track query variables for mysql_query fixes
                query_match = re.search(r'\$(\w+)\s*=\s*["\']', line)
                if query_match:
                    query_var = query_match.group(1)
                    query_vars[query_var] = params
    
    # Now fix mysql_query calls that use the fixed query variables
    for idx, line, label, prob, reports in results:
        if label == "unsafe":
            # Check if this is a mysql_query line
            for query_var, params in query_vars.items():
                if query_var in line and 'mysql_query' in line:
                    fixed = fix_mysql_query_unsafe(line, query_var, params)
                    if fixed:
                        fixed_lines[idx - 1] = fixed
                        fixes_applied.append((idx, line, fixed, params))
                        fixed_line_nums.add(idx)  # Mark original line as fixed
                        
                        # If fix spans multiple lines, mark all new lines as fixed
                        if '\n' in fixed:
                            fix_line_count = fixed.count('\n') + 1
                            for i in range(idx, idx + fix_line_count):
                                fixed_line_nums.add(i)
                    break
    
    return fixed_lines, fixes_applied, fixed_line_nums

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
