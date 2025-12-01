# Testing Guide for New Features

## Quick Start

Your Flask server should already be running at http://127.0.0.1:5000

If not, run:
```bash
cd web
python app.py
```

---

## Test 1: "No Vulnerabilities" Success Message

**Test File**: `test_samples/test_safe.php`

**Expected Result**:
- ✅ Green success banner: "No Vulnerabilities Detected!"
- Shows total lines scanned
- Collapsible "View Code Details" button
- All lines marked as safe (green)

**How to Test**:
1. Go to http://127.0.0.1:5000
2. Upload `test_samples/test_safe.php`
3. Click "Scan"
4. Verify green success message appears
5. Click "▼ View Code Details" to expand/collapse

---

## Test 2: Collapsible Before/After Sections

**Test File**: `test_samples/test_unsafe.php` OR any file from `data/train/unsafe/`

**Expected Result**:
- ⚠️ Yellow disclaimer banner appears
- Before/After code comparison shown
- Click "⚠️ Before (Unsafe Code)" header → collapses/expands
- Click "✅ After (Fixed Code)" header → collapses/expands
- Toggle icons change: ▼ (expanded) ↔ ▶ (collapsed)

**How to Test**:
1. Upload `test_samples/test_unsafe.php`
2. Click "Scan"
3. Verify disclaimer banner appears
4. Click the "Before" header → section collapses
5. Click again → section expands
6. Repeat for "After" header

---

## Test 3: Improved Fixes Validation

**Test File**: `test_samples/test_unsafe.php`

**Expected Result**:
- Fixed code uses `?` placeholders (not string concatenation)
- Fixed code uses `mysqli_prepare()` or PDO (not `mysql_query()`)
- Disclaimer warns about manual review

**How to Test**:
1. Upload `test_samples/test_unsafe.php`
2. Click "Scan"
3. Look at the "After (Fixed Code)" section
4. Verify lines use prepared statements:
   - Should see `?` placeholders
   - Should see `prepare()` or `mysqli_prepare()`
   - Should NOT see string concatenation (`. $var .`)

---

## Test 4: Download Fixed Code

**Test File**: Any unsafe PHP file

**Expected Result**:
- Download button appears
- Downloaded file contains fixed code
- File is valid PHP syntax

**How to Test**:
1. Upload any unsafe PHP file
2. Click "Scan"
3. Click "Download Fixed Code" button
4. Open downloaded file
5. Verify it contains the fixed code with prepared statements

---

## Test 5: Past Scans History

**Expected Result**:
- Past scans appear in sidebar
- Click on past scan → loads results
- Shows filename, timestamp, vulnerability count

**How to Test**:
1. Upload and scan 2-3 different files
2. Check the "Past Scans" section in sidebar
3. Click on a past scan
4. Verify results load correctly

---

## Common Test Files

### Safe Files (Should show green success):
- `test_samples/test_safe.php` (created)
- `data/train/safe/CWE_89__array-GET__CAST-cast_float__multiple_AS-concatenation_simple_quote.php`

### Unsafe Files (Should show fixes):
- `test_samples/test_unsafe.php` (created)
- `data/train/unsafe/CWE_89__array-GET__func_FILTER-CLEANING-email_filter__join-concatenation_simple_quote.php`

---

## Troubleshooting

### Issue: Database error "no such column"
**Solution**: 
```bash
cd web
python migrate_database.py
```

### Issue: Flask not starting
**Solution**:
```bash
# Stop any running Flask instances (CTRL+C)
cd web
python app.py
```

### Issue: Port 5000 already in use
**Solution**:
```bash
# Kill process on port 5000
netstat -ano | findstr :5000
taskkill /PID <PID_NUMBER> /F
```

### Issue: Model version warnings
**Note**: These are just warnings, not errors. The app will still work fine.

---

## Screenshots to Take for Report

1. **Clean Code Success**: Upload `test_safe.php` → Green banner
2. **Vulnerability Detection**: Upload `test_unsafe.php` → Before/After comparison
3. **Collapsible Sections**: Show expanded and collapsed states
4. **Disclaimer Banner**: Yellow warning banner
5. **Download Feature**: Show download button and fixed file
6. **Past Scans**: Show scan history sidebar

---

## Performance Benchmarks

**Expected Performance**:
- Small files (<100 lines): <1 second
- Medium files (100-1000 lines): 1-2 seconds
- Large files (1000-10000 lines): 2-5 seconds

**Test Command**:
```bash
cd web
python -m scripts.detect_lines --file ../test_samples/test_unsafe.php --model ../models/logreg_model.pkl --vectorizer ../models/tfidf_vectorizer.pkl --threshold 0.7
```

---

## What to Report in Deliverable 2

### Working Features ✅
- ML-based vulnerability detection (95.6% recall)
- Automated code fixing (70-80% success rate)
- "No vulnerabilities" success message
- Collapsible Before/After sections
- Disclaimer banner for fix validation
- Download fixed code
- Scan history tracking
- Database integration

### Known Limitations ⚠️
- SQL injection only (no XSS, CSRF, etc.)
- Some complex queries need manual review
- Lower precision (39.8%) means some false positives
- Pattern-based fixes may not cover all edge cases

### Future Improvements 🚀
- Multi-language support
- IDE integration
- Real-time scanning
- Improved ML model precision
- Expanded vulnerability coverage

---

**Last Updated**: November 21, 2025
**Status**: Ready for testing and demo
