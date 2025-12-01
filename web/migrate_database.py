#!/usr/bin/env python3
"""
Migrate SQLite database to add missing columns
"""
import sqlite3
import os

db_path = 'instance/scans.db'

if not os.path.exists(db_path):
    print(f"❌ Database not found at {db_path}")
    exit(1)

print(f"🔧 Migrating database at {db_path}")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check current schema
cursor.execute("PRAGMA table_info(scan)")
columns = [row[1] for row in cursor.fetchall()]
print(f"📋 Current columns: {columns}")

# Add missing columns if they don't exist
migrations = [
    ("total_lines", "ALTER TABLE scan ADD COLUMN total_lines INTEGER DEFAULT 0"),
    ("unsafe_lines", "ALTER TABLE scan ADD COLUMN unsafe_lines INTEGER DEFAULT 0"),
    ("safe_lines", "ALTER TABLE scan ADD COLUMN safe_lines INTEGER DEFAULT 0"),
    ("file_size", "ALTER TABLE scan ADD COLUMN file_size INTEGER DEFAULT 0")
]

for col_name, sql in migrations:
    if col_name not in columns:
        try:
            cursor.execute(sql)
            print(f"✅ Added column: {col_name}")
        except sqlite3.OperationalError as e:
            print(f"⚠️  Column {col_name} already exists or error: {e}")
    else:
        print(f"✓ Column {col_name} already exists")

conn.commit()
conn.close()

print("✅ Migration complete!")
print("\n🚀 You can now restart Flask: python app.py")
