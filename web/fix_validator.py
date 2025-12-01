#!/usr/bin/env python3
"""
Fix Validator - Validates that generated fixes are actually secure
"""

import re

class FixValidator:
    """Validates security fixes to ensure they actually prevent vulnerabilities"""
    
    def __init__(self):
        self.validation_results = []
    
    def validate_sql_injection_fix(self, original_line, fixed_line):
        """
        Validate that a SQL injection fix is secure
        Returns: (is_secure: bool, issues: list, confidence: str)
        """
        issues = []
        is_secure = True
        
        # Check 1: Fixed line should use prepared statements (? placeholders)
        if '?' not in fixed_line and 'prepare' not in fixed_line.lower():
            issues.append("Fix does not use prepared statements or parameterized queries")
            is_secure = False
        
        # Check 2: Should not contain direct variable concatenation in SQL
        if re.search(r'["\']\s*\.\s*\$\w+|\$\w+\s*\.\s*["\']', fixed_line):
            issues.append("Fix still contains string concatenation with variables")
            is_secure = False
        
        # Check 3: Should not have variable interpolation in double quotes with SQL keywords
        if re.search(r'"[^"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$\w+', fixed_line, re.IGNORECASE):
            issues.append("Fix still contains variable interpolation in SQL query string")
            is_secure = False
        
        # Check 4: Should not use deprecated mysql_* functions
        if re.search(r'\bmysql_(query|real_escape_string)\b', fixed_line):
            issues.append("Fix uses deprecated mysql_* functions instead of mysqli or PDO")
            is_secure = False
        
        # Check 5: If using sprintf, should use safe format specifiers
        if 'sprintf' in fixed_line.lower():
            if re.search(r'%s', fixed_line):
                issues.append("Fix uses unsafe %s format specifier in sprintf")
                is_secure = False
            elif not re.search(r'%[duf]', fixed_line):
                issues.append("Fix uses sprintf but no safe format specifiers found")
        
        # Determine confidence level
        if is_secure:
            confidence = "HIGH"
        elif len(issues) == 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return is_secure, issues, confidence
    
    def validate_all_fixes(self, fixes_applied):
        """
        Validate all fixes that were applied
        Returns: dict with validation summary
        """
        validation_summary = {
            'total_fixes': len(fixes_applied),
            'secure_fixes': 0,
            'insecure_fixes': 0,
            'details': []
        }
        
        for line_num, original, fixed, params in fixes_applied:
            is_secure, issues, confidence = self.validate_sql_injection_fix(original, fixed)
            
            validation_summary['details'].append({
                'line': line_num,
                'is_secure': is_secure,
                'confidence': confidence,
                'issues': issues,
                'original': original.strip(),
                'fixed': fixed.strip()
            })
            
            if is_secure:
                validation_summary['secure_fixes'] += 1
            else:
                validation_summary['insecure_fixes'] += 1
        
        return validation_summary
    
    def generate_validation_report(self, validation_summary):
        """Generate a human-readable validation report"""
        total = validation_summary['total_fixes']
        secure = validation_summary['secure_fixes']
        insecure = validation_summary['insecure_fixes']
        
        report = f"""
# Fix Validation Report

## Summary
- Total fixes applied: {total}
- Secure fixes: {secure} ({secure/total*100:.1f}% if total > 0 else 0)
- Fixes needing review: {insecure} ({insecure/total*100:.1f}% if total > 0 else 0)

## Detailed Results

"""
        
        for detail in validation_summary['details']:
            status = "✅ SECURE" if detail['is_secure'] else "⚠️ NEEDS REVIEW"
            report += f"""
### Line {detail['line']} - {status} (Confidence: {detail['confidence']})

**Original:**
```php
{detail['original']}
```

**Fixed:**
```php
{detail['fixed']}
```
"""
            if detail['issues']:
                report += "\n**Issues Found:**\n"
                for issue in detail['issues']:
                    report += f"- {issue}\n"
            
            report += "\n---\n"
        
        return report


def validate_fixes(fixes_applied):
    """Convenience function to validate fixes"""
    validator = FixValidator()
    return validator.validate_all_fixes(fixes_applied)
