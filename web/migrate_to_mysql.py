#!/usr/bin/env python3
"""
Migration script to move data from SQLite to MySQL
"""

import sqlite3
import os
import sys
from sqlalchemy import create_engine, text
import json

def migrate_sqlite_to_mysql():
    """Migrate data from SQLite to MySQL"""
    
    # SQLite connection
    sqlite_path = 'instance/scans.db'
    if not os.path.exists(sqlite_path):
        print(f"SQLite database not found at {sqlite_path}")
        return False
    
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_cursor = sqlite_conn.cursor()
    
    # MySQL connection
    mysql_url = os.environ.get('DATABASE_URL', 'mysql+pymysql://threat_user:threat_password@localhost:3306/threat_scope')
    mysql_engine = create_engine(mysql_url)
    
    try:
        # Test MySQL connection
        with mysql_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ MySQL connection successful")
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
        return False
    
    try:
        # Get data from SQLite
        sqlite_cursor.execute("SELECT * FROM scan")
        rows = sqlite_cursor.fetchall()
        
        print(f"📊 Found {len(rows)} records in SQLite database")
        
        if len(rows) == 0:
            print("No data to migrate")
            return True
        
        # Get column names
        column_names = [description[0] for description in sqlite_cursor.description]
        print(f"Columns: {column_names}")
        
        # Migrate data
        with mysql_engine.connect() as mysql_conn:
            # Clear existing data
            mysql_conn.execute(text("DELETE FROM scan"))
            mysql_conn.commit()
            
            # Insert data
            for row in rows:
                # Create a dictionary from the row data
                row_dict = dict(zip(column_names, row))
                
                # Handle the case where new columns might not exist in old data
                insert_data = {
                    'id': row_dict.get('id'),
                    'filename': row_dict.get('filename'),
                    'timestamp': row_dict.get('timestamp'),
                    'results': row_dict.get('results'),
                    'total_lines': row_dict.get('total_lines', 0),
                    'unsafe_lines': row_dict.get('unsafe_lines', 0),
                    'safe_lines': row_dict.get('safe_lines', 0),
                    'file_size': row_dict.get('file_size', 0)
                }
                
                # If we don't have the new columns, try to calculate them from results
                if insert_data['total_lines'] == 0 and insert_data['results']:
                    try:
                        results = json.loads(insert_data['results'])
                        insert_data['total_lines'] = len(results)
                        insert_data['unsafe_lines'] = sum(1 for r in results if r.get('label') == 'unsafe')
                        insert_data['safe_lines'] = sum(1 for r in results if r.get('label') == 'safe')
                    except:
                        pass
                
                # Insert the record
                insert_sql = text("""
                    INSERT INTO scan (id, filename, timestamp, results, total_lines, unsafe_lines, safe_lines, file_size)
                    VALUES (:id, :filename, :timestamp, :results, :total_lines, :unsafe_lines, :safe_lines, :file_size)
                """)
                
                mysql_conn.execute(insert_sql, insert_data)
            
            mysql_conn.commit()
            print(f"✅ Successfully migrated {len(rows)} records to MySQL")
            
            # Verify migration
            result = mysql_conn.execute(text("SELECT COUNT(*) FROM scan"))
            count = result.scalar()
            print(f"✅ MySQL now contains {count} records")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False
    finally:
        sqlite_conn.close()
    
    return True

if __name__ == "__main__":
    print("🔄 Starting SQLite to MySQL migration...")
    success = migrate_sqlite_to_mysql()
    if success:
        print("✅ Migration completed successfully!")
    else:
        print("❌ Migration failed!")
        sys.exit(1)
