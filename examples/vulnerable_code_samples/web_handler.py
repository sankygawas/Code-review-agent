"""
Example: Web request handler with security vulnerabilities
This file contains intentionally vulnerable code for demonstration purposes.
"""

import subprocess
import os
from flask import request, render_template_string

# ❌ SECURITY ISSUE: Exposed API tokens
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

class WebHandler:
    def render_user_profile(self, user_input):
        """❌ SECURITY ISSUE: XSS vulnerability"""
        # Direct insertion of user input into HTML
        html = f"<div>Welcome {user_input}!</div>"
        return html
    
    def render_dynamic_content(self, template, user_data):
        """❌ SECURITY ISSUE: Template injection"""
        # Using user-controlled template content
        return render_template_string(template, data=user_data)
    
    def execute_system_command(self, cmd):
        """❌ SECURITY ISSUE: Command injection vulnerability"""
        # Direct execution of user-provided commands
        result = os.system(f"ls {cmd}")
        return result

    def process_file(self, filename):
        """❌ SECURITY ISSUE: Another command injection"""
        # Shell=True with user input is dangerous
        output = subprocess.call(f"cat {filename}", shell=True)
        return output
    
    def run_script(self, script_name, args):
        """❌ SECURITY ISSUE: Command injection via subprocess"""
        # User input directly passed to shell
        command = f"python {script_name} {args}"
        process = subprocess.Popen(command, shell=True, capture_output=True)
        return process.communicate()
    
    def evaluate_expression(self, expr):
        """❌ SECURITY ISSUE: Code injection via eval"""
        # Never use eval with user input!
        return eval(expr)
    
    def generate_report(self, user_id):
        """❌ SECURITY ISSUE: Path traversal vulnerability"""
        # User input used in file path without validation
        file_path = f"/reports/user_{user_id}.txt"
        with open(file_path, 'r') as f:
            return f.read()
    
    def set_user_preferences(self, preferences):
        """❌ SECURITY ISSUE: Insecure deserialization"""
        import pickle
        # Deserializing user-provided data is dangerous
        user_prefs = pickle.loads(preferences)
        return user_prefs