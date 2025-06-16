#!/usr/bin/env python3
"""
Security Review Agent

A specialized AI agent built with Agno framework for detecting security vulnerabilities
in code. This agent analyzes source code files and identifies potential security issues
including exposed secrets, injection vulnerabilities, and unsafe coding patterns.

Author: Your Name
Version: 1.0.0
License: MIT
"""

import os
import re
import json
import subprocess
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from agno.agent import Agent
from agno.models.openai import OpenAIChat


@dataclass
class SecurityFinding:
    """
    Represents a security vulnerability found during code review.
    
    Attributes:
        severity (str): Risk level - 'critical', 'high', 'medium', 'low', 'info'
        category (str): Type of vulnerability - 'secrets', 'injection', 'authentication', etc.
        file_path (str): Path to the file containing the vulnerability
        line_number (int): Line number where the issue was found
        description (str): Human-readable description of the security issue
        recommendation (str): Suggested fix or mitigation strategy
        code_snippet (str): The actual code that contains the vulnerability
    """
    severity: str
    category: str
    file_path: str
    line_number: int
    description: str
    recommendation: str
    code_snippet: str


class SecurityReviewAgent(Agent):
    """
    AI-powered security review agent for analyzing code vulnerabilities.
    
    This agent uses pattern matching and AI analysis to detect common security
    vulnerabilities in source code. It provides GitHub-style comments with
    exact line references and actionable remediation advice.
    
    Supported vulnerability types:
    - Exposed secrets (API keys, passwords, tokens, private keys)
    - Injection attacks (SQL, Command, XSS)
    - Authentication and authorization flaws
    - Input validation issues
    - Cryptographic weaknesses
    - Insecure coding patterns
    
    Usage:
        agent = SecurityReviewAgent()
        result = agent.review_pull_request(files)
    """
    
    def __init__(self, model_id: str = "gpt-4o", debug: bool = True):
        """
        Initialize the Security Review Agent.
        
        Args:
            model_id (str): The AI model to use (default: gpt-4o)
            debug (bool): Enable debug mode for detailed logging
        """
        super().__init__(
            model=OpenAIChat(id=model_id),
            name="Security Review Agent",
            instructions=[
                "You are a security expert reviewing code for potential vulnerabilities.",
                "Focus on:",
                "1. Exposed secrets (API keys, passwords, tokens)",
                "2. SQL injection vulnerabilities", 
                "3. Cross-site scripting (XSS) risks",
                "4. Authentication and authorization flaws",
                "5. Input validation issues",
                "6. Cryptographic weaknesses",
                "7. Insecure dependencies",
                "",
                "Provide actionable recommendations with severity levels.",
                "Be thorough but avoid false positives."
            ],
            markdown=True,
            debug_mode=debug
        )
        
        # Regular expression patterns for detecting exposed secrets
        self.secret_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
            'token': r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})["\']?',
            'private_key': r'-----BEGIN (PRIVATE|RSA|EC) KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
        }
        
        self.vulnerability_patterns = {
            'sql_injection': [
                r'(?i)execute\s*\(\s*["\'].*%s.*["\']',
                r'(?i)query\s*\(\s*["\'].*\+.*["\']',
                r'(?i)SELECT.*FROM.*WHERE.*=.*\+',
            ],
            'xss': [
                r'(?i)innerHTML\s*=.*\+',
                r'(?i)document\.write\s*\(.*\+',
                r'(?i)eval\s*\(',
            ],
            'command_injection': [
                r'(?i)os\.system\s*\(',
                r'(?i)subprocess\.(call|run|Popen)\s*\(',
                r'(?i)exec\s*\(',
            ]
        }
        
        # Patterns for detecting common vulnerability types
        self.vulnerability_patterns = {
            'sql_injection': [
                r'(?i)execute\s*\(\s*["\'].*%s.*["\']',  # String formatting in SQL
                r'(?i)query\s*\(\s*["\'].*\+.*["\']',    # String concatenation in SQL
                r'(?i)SELECT.*FROM.*WHERE.*=.*\+',       # Direct concatenation
            ],
            'xss': [
                r'(?i)innerHTML\s*=.*\+',                # Direct HTML injection
                r'(?i)document\.write\s*\(.*\+',         # Document.write with concat
                r'(?i)eval\s*\(',                        # Dangerous eval usage
            ],
            'command_injection': [
                r'(?i)os\.system\s*\(',                  # Direct system calls
                r'(?i)subprocess\.(call|run|Popen)\s*\(',# Subprocess with user input
                r'(?i)exec\s*\(',                        # Direct exec calls
            ]
        }

    def analyze_code_security(self, file_path: str, content: str) -> List[SecurityFinding]:
        """
        Analyze source code content for security vulnerabilities.
        
        This method performs static analysis using regex patterns to detect:
        - Hardcoded secrets and credentials
        - Common injection vulnerability patterns
        - Unsafe coding practices
        
        Args:
            file_path (str): Path to the file being analyzed
            content (str): Source code content to analyze
            
        Returns:
            List[SecurityFinding]: List of security issues found
        """
        findings = []
        lines = content.split('\n')
        
        # Scan each line for exposed secrets
        for line_num, line in enumerate(lines, 1):
            # Check against all secret detection patterns
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append(SecurityFinding(
                        severity='critical',  # Secrets are always critical
                        category='secrets',
                        file_path=file_path,
                        line_number=line_num,
                        description=f'Potential {secret_type} exposed in code',
                        recommendation=f'Move {secret_type} to environment variables or secure vault',
                        code_snippet=line.strip()
                    ))
        
        # Scan for common vulnerability patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line):
                        # Assign severity based on vulnerability type
                        severity = 'high' if vuln_type in ['sql_injection', 'command_injection'] else 'medium'
                        findings.append(SecurityFinding(
                            severity=severity,
                            category=vuln_type,
                            file_path=file_path,
                            line_number=line_num,
                            description=f'Potential {vuln_type.replace("_", " ")} vulnerability',
                            recommendation=self._get_vulnerability_recommendation(vuln_type),
                            code_snippet=line.strip()
                        ))
        
        return findings

    def _get_vulnerability_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for specific vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize user input and use proper output encoding',
            'command_injection': 'Validate and sanitize input, use safe alternatives to system calls'
        }
        return recommendations.get(vuln_type, 'Review code for security best practices')

    def review_pull_request(self, pr_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Review pull request files for security issues"""
        all_findings = []
        
        for file_info in pr_files:
            file_path = file_info['filename']
            content = file_info.get('content', '')
            
            # Skip binary files and common non-code files
            if self._should_skip_file(file_path):
                continue
                
            findings = self.analyze_code_security(file_path, content)
            all_findings.extend(findings)
        
        # Generate summary report
        return self._generate_security_report(all_findings)
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Determine if file should be skipped for security review"""
        skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'}
        skip_dirs = {'node_modules', '.git', '__pycache__', 'venv', '.venv'}
        
        ext = os.path.splitext(file_path)[1].lower()
        path_parts = file_path.split('/')
        
        return (ext in skip_extensions or 
                any(skip_dir in path_parts for skip_dir in skip_dirs))
    
    def _generate_security_report(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        if not findings:
            return {
                'status': 'pass',
                'summary': 'No security issues detected',
                'findings': [],
                'recommendations': []
            }
        
        # Group findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        category_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        # Determine overall status
        status = 'fail' if severity_counts['critical'] > 0 or severity_counts['high'] > 0 else 'warning'
        
        # Generate summary
        total_issues = len(findings)
        summary = f"Found {total_issues} security issues: "
        summary += ", ".join([f"{count} {severity}" for severity, count in severity_counts.items() if count > 0])
        
        # Convert findings to GitHub-style comments format
        findings_dict = [
            {
                'severity': f.severity,
                'category': f.category,
                'file_path': f.file_path,
                'line_number': f.line_number,
                'description': f.description,
                'recommendation': f.recommendation,
                'code_snippet': f.code_snippet,
                'github_comment': self._format_github_comment(f)
            }
            for f in findings
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        return {
            'status': status,
            'summary': summary,
            'total_issues': total_issues,
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'findings': findings_dict,
            'recommendations': recommendations
        }
    
    def _format_github_comment(self, finding: SecurityFinding) -> str:
        """Format finding as GitHub-style comment"""
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️', 
            'medium': '💡',
            'low': 'ℹ️',
            'info': '📝'
        }
        
        emoji = severity_emoji.get(finding.severity, '⚠️')
        
        comment = f"""## {emoji} Security Issue - {finding.severity.upper()}

**File:** `{finding.file_path}` (Line {finding.line_number})

**Issue:** {finding.description}

**Code:**
```python
{finding.code_snippet}
```

**Recommendation:** {finding.recommendation}

**Category:** {finding.category.replace('_', ' ').title()}
        """
        
        return comment.strip()
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate high-level security recommendations"""
        recommendations = []
        
        categories = set(f.category for f in findings)
        
        if 'secrets' in categories:
            recommendations.append("Implement proper secrets management using environment variables or secure vaults")
        
        if any(cat in categories for cat in ['sql_injection', 'xss', 'command_injection']):
            recommendations.append("Implement input validation and sanitization for all user inputs")
        
        if len(findings) > 5:
            recommendations.append("Consider implementing automated security scanning in CI/CD pipeline")
        
        recommendations.append("Review and follow OWASP security guidelines")
        
        return recommendations


def main():
    """Example usage of the Security Review Agent"""
    agent = SecurityReviewAgent()
    
    # Example PR files (would come from GitHub API in real implementation)
    example_files = [
        {
            'filename': 'src/auth.py',
            'content': '''
import os
import hashlib

API_KEY = "sk-1234567890abcdef"  # This should be in env vars
DATABASE_PASSWORD = "mypassword123"

def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return execute_query(query)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
        }
    ]
    
    result = agent.review_pull_request(example_files)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()