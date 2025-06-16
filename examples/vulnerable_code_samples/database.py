"""
Example: Database connection with security vulnerabilities
This file contains intentionally vulnerable code for demonstration purposes.
"""

import sqlite3
import os

# ❌ SECURITY ISSUE: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-proj-1234567890abcdefghijklmnop"
DATABASE_URL = "postgresql://user:password123@localhost/mydb"

class UserDatabase:
    def __init__(self):
        # ❌ SECURITY ISSUE: Database credentials in code
        self.connection_string = "mysql://root:mysecretpassword@localhost/users"
    
    def get_user_data(self, user_id):
        """❌ SECURITY ISSUE: SQL Injection vulnerability"""
        conn = sqlite3.connect('app.db')
        # Dangerous: Direct string interpolation allows SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor = conn.execute(query)
        return cursor.fetchall()

    def search_users(self, search_term):
        """❌ SECURITY ISSUE: Another SQL injection vulnerability"""
        # String concatenation in SQL queries is dangerous
        query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
        return self.execute_query(query)
    
    def authenticate_user(self, username, password):
        """❌ SECURITY ISSUE: Multiple vulnerabilities"""
        # SQL injection + weak password hashing
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        result = self.execute_query(query)
        
        # ❌ Weak hashing algorithm
        import hashlib
        hashed = hashlib.md5(password.encode()).hexdigest()
        return result and hashed
    
    def execute_query(self, query):
        """Helper method for database queries"""
        # Implementation would go here
        pass