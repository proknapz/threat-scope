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
        if re.search(r'\$_(?:GET|POST|REQUEST)\[', code_line) and 'SELECT' in code_line.upper():
            original = code_line
            # Suggest prepared statement
            fixed = self._suggest_prepared_statement(code_line)
            fixes.append({
                'line': line_num,
                'type': 'SQL Injection - Direct Concatenation',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Replaced direct concatenation with prepared statement'
            })
            
        # Pattern 2: mysql_query with variables
        if 'mysql_query' in code_line and '$' in code_line:
            original = code_line
            fixed = code_line.replace('mysql_query', 'mysqli_prepare')
            fixes.append({
                'line': line_num,
                'type': 'SQL Injection - Unsafe Query Function',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Replaced mysql_query with prepared statement'
            })
            
        # Pattern 3: Missing input validation
        if re.search(r'\$_(?:GET|POST|REQUEST)\[.*?\]', code_line):
            var_match = re.search(r'\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)\[', code_line)
            if var_match:
                var_name = var_match.group(1)
                original = code_line
                fixed = f"${var_name} = filter_var($_GET['{var_name}'], FILTER_SANITIZE_STRING);"
                fixes.append({
                    'line': line_num,
                    'type': 'Input Validation Missing',
                    'original': original.strip(),
                    'fixed': fixed,
                    'explanation': 'Added input sanitization'
                })
                
        return fixes
    
    def _suggest_prepared_statement(self, code_line):
        """Convert unsafe query to prepared statement"""
        # This is a simplified example - real implementation would be more sophisticated
        if 'SELECT' in code_line.upper():
            return "// Use prepared statement: $stmt = $pdo->prepare('SELECT * FROM table WHERE id = ?'); $stmt->execute([$id]);"
        return code_line
    
    def fix_xss_vulnerabilities(self, code_line, line_num):
        """Fix XSS vulnerabilities"""
        fixes = []
        
        # Pattern: Direct echo of user input
        if 'echo' in code_line and re.search(r'\$_(?:GET|POST|REQUEST)\[', code_line):
            original = code_line
            fixed = code_line.replace('echo', 'echo htmlspecialchars(') + ', ENT_QUOTES, "UTF-8")'
            fixes.append({
                'line': line_num,
                'type': 'XSS - Unescaped Output',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Added HTML entity encoding'
            })
            
        return fixes
    
    def fix_command_injection(self, code_line, line_num):
        """Fix command injection vulnerabilities"""
        fixes = []
        
        # Pattern: system() with user input
        if 'system(' in code_line and '$' in code_line:
            original = code_line
            fixed = "// Use escapeshellarg() to sanitize input before system() call"
            fixes.append({
                'line': line_num,
                'type': 'Command Injection',
                'original': original.strip(),
                'fixed': fixed,
                'explanation': 'Command execution with user input detected - use escapeshellarg()'
            })
            
        return fixes
    
    def analyze_and_fix_file(self, file_path, vulnerabilities):
        """Analyze file and generate fixes for detected vulnerabilities"""
        all_fixes = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for vuln in vulnerabilities:
            line_num = vuln['line_num']
            if line_num <= len(lines):
                code_line = lines[line_num - 1]
                
                # Apply different fix strategies based on vulnerability type
                fixes = []
                fixes.extend(self.fix_sql_injection(code_line, line_num))
                fixes.extend(self.fix_xss_vulnerabilities(code_line, line_num))
                fixes.extend(self.fix_command_injection(code_line, line_num))
                
                all_fixes.extend(fixes)
        
        return all_fixes
    
    def generate_fix_report(self, file_path, fixes):
        """Generate a detailed fix report"""
        report = f"""
# Security Fix Report for {file_path}

## Summary
- Total vulnerabilities found: {len(fixes)}
- Fixes generated: {len(fixes)}

## Detailed Fixes

"""
        
        for i, fix in enumerate(fixes, 1):
            report += f"""
### Fix #{i}: {fix['type']}
**Line {fix['line']}**

**Original Code:**
```php
{fix['original']}
```

**Suggested Fix:**
```php
{fix['fixed']}
```

**Explanation:** {fix['explanation']}

---
"""
        
        return report

def main():
    """Example usage"""
    mitigator = CodeMitigator()
    
    # Example vulnerabilities (would come from your detection system)
    sample_vulns = [
        {'line_num': 6, 'type': 'sql_injection'},
        {'line_num': 10, 'type': 'sql_injection'},
    ]
    
    test_file = "test_samples/sql_injection_test.php"
    if os.path.exists(test_file):
        fixes = mitigator.analyze_and_fix_file(test_file, sample_vulns)
        report = mitigator.generate_fix_report(test_file, fixes)
        
        # Save report
        with open("results/fix_report.md", "w") as f:
            f.write(report)
            
        print(f"Generated {len(fixes)} fixes. Report saved to results/fix_report.md")
    else:
        print(f"Test file {test_file} not found")

if __name__ == "__main__":
    main()
