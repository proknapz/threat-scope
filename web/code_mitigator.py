#!/usr/bin/env python3
"""
Code Mitigator - Automatically fix detected vulnerabilities
Implements secure coding patterns while preserving functionality
"""

import re
import os
from pathlib import Path

class CodeMitigator:
    def __init__(self):
        self.fixes_applied = []
        
    def fix_sql_injection(self, code_line, line_num):
        """Fix SQL injection vulnerabilities"""
        fixes = []
        
        # Pattern 1: Direct concatenation with user input
        if re.search(r'\$_(?:GET|POST|REQUEST)\[', code_line) and any(sql_word in code_line.upper() for sql_word in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
            original = code_line
            # Suggest prepared statement
            fixed = "// FIXED: Use prepared statements instead of direct concatenation\n" + \
                   "// $stmt = $pdo->prepare('SELECT * FROM table WHERE column = ?');\n" + \
                   "// $stmt->execute([$user_input]);"
            fixes.append({
                'line': line_num,
                'type': 'SQL Injection - Direct Concatenation',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Replaced direct string concatenation with prepared statements to prevent SQL injection. Direct concatenation allows user input to be interpreted as SQL code, enabling attackers to modify queries. Prepared statements use parameterized queries where user input is treated as data only, completely eliminating SQL injection vulnerabilities.'
            })
            
        # Pattern 2: mysql_query with variables
        if 'mysql_query' in code_line and '$' in code_line:
            original = code_line
            fixed = "// FIXED: Replace mysql_query with prepared statements\n" + \
                   "// $stmt = mysqli_prepare($connection, 'SELECT * FROM table WHERE id = ?');\n" + \
                   "// mysqli_stmt_bind_param($stmt, 'i', $id);\n" + \
                   "// mysqli_stmt_execute($stmt);"
            fixes.append({
                'line': line_num,
                'type': 'SQL Injection - Deprecated Function',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Replaced deprecated mysql_query with prepared statement using mysqli. The mysql_query() function is deprecated and vulnerable to SQL injection. Prepared statements separate SQL code from data, preventing injection attacks by treating user input as data only, never as executable code. This approach is more secure and also provides better performance through query plan caching.'
            })
            
        # Pattern 3: Missing input validation
        if re.search(r'\$_(?:GET|POST|REQUEST)\[.*?\]', code_line) and 'filter_var' not in code_line:
            var_match = re.search(r'\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)\[([\'"]?)(\w+)\2\]', code_line)
            if var_match:
                var_name = var_match.group(1)
                input_name = var_match.group(3)
                original = code_line
                fixed = f"// FIXED: Add input validation and sanitization\n" + \
                       f"${var_name} = filter_var($_GET['{input_name}'], FILTER_SANITIZE_STRING);\n" + \
                       f"if (${var_name} === false) {{\n" + \
                       f"    die('Invalid input');\n" + \
                       f"}}"
                fixes.append({
                    'line': line_num,
                    'type': 'Input Validation Missing',
                    'original': original.strip(),
                    'fixed': fixed,
                    'explanation': 'Added input validation and sanitization using filter_var() to prevent malicious input. Raw user input from $_GET, $_POST, and $_REQUEST should never be used directly. Input validation ensures data meets expected format requirements, while sanitization removes potentially dangerous characters. This creates a defense-in-depth approach to security.'
                })
                
        return fixes
    
    def fix_xss_vulnerabilities(self, code_line, line_num):
        """Fix XSS vulnerabilities"""
        fixes = []
        
        # Pattern: Direct echo of user input
        if 'echo' in code_line and re.search(r'\$_(?:GET|POST|REQUEST)\[', code_line):
            original = code_line
            # Extract the variable being echoed
            var_match = re.search(r'echo\s+(\$_(?:GET|POST|REQUEST)\[[\'"]?\w+[\'"]?\])', code_line)
            if var_match:
                var = var_match.group(1)
                fixed = f"// FIXED: Escape output to prevent XSS\n" + \
                       f"echo htmlspecialchars({var}, ENT_QUOTES, 'UTF-8');"
            else:
                fixed = "// FIXED: Use htmlspecialchars() to escape output\n" + \
                       "echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');"
            
            fixes.append({
                'line': line_num,
                'type': 'XSS - Unescaped Output',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Added HTML entity encoding to prevent Cross-Site Scripting (XSS)'
            })
            
        return fixes
    
    def fix_command_injection(self, code_line, line_num):
        """Fix command injection vulnerabilities"""
        fixes = []
        
        # Pattern: system() with user input
        if any(func in code_line for func in ['system(', 'exec(', 'shell_exec(', 'passthru(']):
            original = code_line
            fixed = "// FIXED: Validate and escape shell arguments\n" + \
                   "// $safe_arg = escapeshellarg($user_input);\n" + \
                   "// system('command ' . $safe_arg);\n" + \
                   "// OR better: use specific PHP functions instead of shell commands"
            fixes.append({
                'line': line_num,
                'type': 'Command Injection',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Use escapeshellarg() or avoid shell commands entirely to prevent command injection'
            })
            
        return fixes
    
    def fix_file_inclusion(self, code_line, line_num):
        """Fix file inclusion vulnerabilities"""
        fixes = []
        
        # Pattern: include/require with user input
        if any(func in code_line for func in ['include(', 'require(', 'include_once(', 'require_once(']):
            if re.search(r'\$_(?:GET|POST|REQUEST)\[', code_line):
                original = code_line
                fixed = "// FIXED: Validate file paths and use whitelist\n" + \
                       "// $allowed_files = ['page1.php', 'page2.php', 'page3.php'];\n" + \
                       "// $file = $_GET['page'];\n" + \
                       "// if (in_array($file, $allowed_files)) {\n" + \
                       "//     include($file);\n" + \
                       "// } else {\n" + \
                       "//     die('Invalid file');\n" + \
                       "// }"
                fixes.append({
                    'line': line_num,
                    'type': 'File Inclusion Vulnerability',
                    'original': original.strip(),
                    'fixed': fixed,
                    'explanation': 'Use a whitelist of allowed files to prevent Local/Remote File Inclusion'
                })
                
        return fixes
    
    def analyze_and_fix_vulnerabilities(self, scan_results):
        """Analyze scan results and generate fixes"""
        all_fixes = []
        
        for result in scan_results:
            if isinstance(result, dict):
                line_num = result.get('line_num')
                line_content = result.get('line', '')
                label = result.get('label')
            elif isinstance(result, tuple) and len(result) >= 3:
                line_num = result[0]
                line_content = result[1]
                label = result[2]
            else:
                continue
                
            if label == 'unsafe':
                # Apply different fix strategies
                fixes = []
                fixes.extend(self.fix_sql_injection(line_content, line_num))
                fixes.extend(self.fix_xss_vulnerabilities(line_content, line_num))
                fixes.extend(self.fix_command_injection(line_content, line_num))
                fixes.extend(self.fix_file_inclusion(line_content, line_num))
                
                all_fixes.extend(fixes)
        
        return all_fixes
    
    def generate_fix_report(self, fixes, filename=""):
        """Generate a detailed fix report"""
        if not fixes:
            return {
                'summary': {
                    'total_vulnerabilities': 0,
                    'fixes_generated': 0,
                    'file': filename
                },
                'fixes': [],
                'report_text': f"No vulnerabilities found in {filename}"
            }
        
        report_text = f"""
# Security Fix Report for {filename}

## Summary
- Total vulnerabilities found: {len(fixes)}
- Fixes generated: {len(fixes)}
- File: {filename}

## Detailed Fixes

"""
        
        for i, fix in enumerate(fixes, 1):
            report_text += f"""
### Fix #{i}: {fix['type']}
**Line {fix['line']}**

**Vulnerable Code:**
```php
{fix['original']}
```

**Secure Fix:**
```php
{fix['fixed']}
```

**Explanation:** {fix['explanation']}

**Security Impact:** 
- **Before**: Code is vulnerable to {fix['type'].split(' - ')[0]} attacks
- **After**: Input is properly validated/sanitized/escaped

---
"""
        
        return {
            'summary': {
                'total_vulnerabilities': len(fixes),
                'fixes_generated': len(fixes),
                'file': filename
            },
            'fixes': fixes,
            'report_text': report_text
        }

def create_mitigator():
    """Factory function to create a CodeMitigator instance"""
    return CodeMitigator()
