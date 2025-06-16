#!/usr/bin/env python3

from .agent import SecurityReviewAgent
import json


def demo_security_review():
    """Demonstrate the Security Review Agent with example vulnerable code"""
    
    agent = SecurityReviewAgent()
    
    # Example vulnerable code files
    vulnerable_files = [
        {
            'filename': 'src/database.py',
            'content': '''
import sqlite3
import os

# Bad: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-proj-1234567890abcdefghijklmnop"

def get_user_data(user_id):
    conn = sqlite3.connect('app.db')
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return cursor.fetchall()

def search_users(search_term):
    # Another SQL injection vulnerability
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
    return execute_query(query)
'''
        },
        {
            'filename': 'src/web_handler.py',
            'content': '''
import subprocess
import os

def render_template(template_name, user_input):
    # XSS vulnerability
    html = f"<div>Welcome {user_input}!</div>"
    return html

def execute_command(cmd):
    # Command injection vulnerability
    result = os.system(f"ls {cmd}")
    return result

def process_file(filename):
    # Another command injection
    subprocess.call(f"cat {filename}", shell=True)

# Exposed GitHub token
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
'''
        },
        {
            'filename': 'src/crypto.py', 
            'content': '''
import hashlib
import random

def weak_hash(password):
    # Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Weak random generation
    return str(random.randint(1000, 9999))

# Private key in source code
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
xTiHdwfNyAqKPzcRHq2eSgHvPCEG8K7Q4L6U6qGrZqrIX0D7yJ9C+pZsHhHQs7X0
-----END PRIVATE KEY-----"""
'''
        }
    ]
    
    print("🔍 Running Security Review Agent...")
    print("=" * 50)
    
    # Perform security review
    review_result = agent.review_pull_request(vulnerable_files)
    
    # Display results
    print(f"Status: {review_result['status'].upper()}")
    print(f"Summary: {review_result['summary']}")
    print(f"Total Issues: {review_result['total_issues']}")
    print()
    
    print("Severity Breakdown:")
    for severity, count in review_result['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    print()
    
    print("Category Breakdown:")
    for category, count in review_result['category_breakdown'].items():
        print(f"  {category.replace('_', ' ').title()}: {count}")
    print()
    
    print("GitHub-Style Security Comments:")
    print("=" * 50)
    for i, finding in enumerate(review_result['findings'], 1):
        print(f"\n### Finding #{i}")
        print(finding['github_comment'])
        print("\n" + "-" * 80)
    
    print("Recommendations:")
    print("-" * 20)
    for i, rec in enumerate(review_result['recommendations'], 1):
        print(f"{i}. {rec}")
    
    return review_result


if __name__ == "__main__":
    demo_security_review()