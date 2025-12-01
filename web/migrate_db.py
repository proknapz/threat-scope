#!/usr/bin/env python3
"""
Database migration script to add the 'fixes' column to the Scan table.
Run this script to update the database schema.
"""

import os
import sys
import pymysql
import time

# Database configuration
DB_HOST = os.environ.get('MYSQL_HOST', 'mysql')  # Use 'mysql' for Docker
DB_PORT = int(os.environ.get('MYSQL_PORT', '3306'))
DB_USER = os.environ.get('MYSQL_USER', 'threat_user')
DB_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'threat_password')
DB_NAME = os.environ.get('MYSQL_DATABASE', 'threat_scope')

def wait_for_db():
    """Wait for database to be ready"""
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            connection = pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            connection.close()
            print("✅ Database connection successful")
            return True
        except Exception as e:
            retry_count += 1
            print(f"⏳ Waiting for database... (attempt {retry_count}/{max_retries})")
            time.sleep(2)
    
    print("❌ Failed to connect to database")
    return False

def migrate():
    """Add fixes column to scan table"""
    try:
        print("🔄 Starting database migration...")
        
        # Connect to database
        connection = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        
        cursor = connection.cursor()
        
        # Check if column already exists
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s 
            AND TABLE_NAME = 'scan' 
            AND COLUMN_NAME = 'fixes'
        """, (DB_NAME,))
        
        exists = cursor.fetchone()[0]
        
        if exists:
            print("ℹ️  Column 'fixes' already exists, skipping migration")
        else:
            # Add the fixes column
            print("➕ Adding 'fixes' column to scan table...")
            cursor.execute("""
                ALTER TABLE scan 
                ADD COLUMN fixes TEXT AFTER results
            """)
            connection.commit()
            print("✅ Migration completed successfully!")
        
        cursor.close()
        connection.close()
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("🚀 Database Migration Tool")
    print("=" * 50)
    
    if wait_for_db():
        migrate()
    else:
        print("❌ Cannot proceed without database connection")
        sys.exit(1)
