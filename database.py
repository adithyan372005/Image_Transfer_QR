#!/usr/bin/env python3
"""
Database management for CNS project
SQLite database for storing encrypted files and transaction data
"""

import sqlite3
import threading
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_path='secure_transfer.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create transactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    encrypted_file TEXT NOT NULL,
                    encrypted_aes_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    hash_value TEXT NOT NULL,
                    hashed_pin TEXT NOT NULL,
                    attempt_count INTEGER DEFAULT 0,
                    expiry_time TEXT NOT NULL,
                    status TEXT DEFAULT 'ACTIVE',
                    file_name TEXT NOT NULL,
                    huffman_tree TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create temporary files table for downloads
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS temp_files (
                    transaction_id TEXT PRIMARY KEY,
                    file_data BLOB NOT NULL,
                    file_name TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            print("Database initialized successfully")
    
    def store_transaction(self, transaction_id, encrypted_file, encrypted_aes_key, 
                         private_key, hash_value, hashed_pin, expiry_time, 
                         file_name, huffman_tree):
        """Store transaction data in database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO transactions 
                (transaction_id, encrypted_file, encrypted_aes_key, private_key, 
                 hash_value, hashed_pin, expiry_time, file_name, huffman_tree)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_id, encrypted_file, encrypted_aes_key, private_key,
                  hash_value, hashed_pin, expiry_time.isoformat(), file_name, huffman_tree))
            
            conn.commit()
            conn.close()
    
    def get_transaction(self, transaction_id):
        """Retrieve transaction data from database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM transactions WHERE transaction_id = ? AND status = 'ACTIVE'
            ''', (transaction_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
    
    def increment_attempts(self, transaction_id):
        """Increment attempt count for a transaction"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE transactions 
                SET attempt_count = attempt_count + 1 
                WHERE transaction_id = ?
            ''', (transaction_id,))
            
            conn.commit()
            conn.close()
    
    def delete_transaction(self, transaction_id):
        """Delete transaction from database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM transactions WHERE transaction_id = ?', (transaction_id,))
            
            conn.commit()
            conn.close()
    
    def store_temp_file(self, transaction_id, file_data, file_name=None):
        """Store temporary file data for download"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get file name from transaction if not provided
            if not file_name:
                cursor.execute('SELECT file_name FROM transactions WHERE transaction_id = ?', (transaction_id,))
                result = cursor.fetchone()
                file_name = result[0] if result else 'download.pdf'
            
            cursor.execute('''
                INSERT OR REPLACE INTO temp_files (transaction_id, file_data, file_name)
                VALUES (?, ?, ?)
            ''', (transaction_id, file_data, file_name))
            
            conn.commit()
            conn.close()
    
    def get_temp_file(self, transaction_id):
        """Retrieve temporary file data"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT file_data, file_name FROM temp_files WHERE transaction_id = ?
            ''', (transaction_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'data': result['file_data'],
                    'name': result['file_name']
                }
            return None
    
    def delete_temp_file(self, transaction_id):
        """Delete temporary file data"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM temp_files WHERE transaction_id = ?', (transaction_id,))
            
            conn.commit()
            conn.close()
    
    def cleanup_expired_transactions(self):
        """Clean up expired transactions"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            current_time = datetime.now().isoformat()
            cursor.execute('''
                DELETE FROM transactions WHERE expiry_time < ?
            ''', (current_time,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            return deleted_count
    
    def cleanup_old_temp_files(self, hours=1):
        """Clean up old temporary files"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now().replace(hour=datetime.now().hour - hours).isoformat()
            cursor.execute('''
                DELETE FROM temp_files WHERE created_at < ?
            ''', (cutoff_time,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            return deleted_count
    
    def get_stats(self):
        """Get database statistics"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count active transactions
            cursor.execute('SELECT COUNT(*) FROM transactions WHERE status = "ACTIVE"')
            active_transactions = cursor.fetchone()[0]
            
            # Count temp files
            cursor.execute('SELECT COUNT(*) FROM temp_files')
            temp_files = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'active_transactions': active_transactions,
                'temp_files': temp_files
            }