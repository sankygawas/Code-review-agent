"""
Base Agent Class

Provides common functionality for all code review agents including:
- File filtering and processing
- Report generation utilities
- Common configuration options
"""

import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from agno.agent import Agent


class BaseReviewAgent(Agent, ABC):
    """
    Abstract base class for all code review agents.
    
    Provides common functionality including file filtering, report generation,
    and standardized interfaces for all review agents.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the base review agent."""
        super().__init__(*args, **kwargs)
        
        # Common file extensions to skip during review
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',  # Images
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Documents
            '.zip', '.tar', '.gz', '.rar', '.7z',  # Archives
            '.mp4', '.avi', '.mov', '.wmv', '.mp3', '.wav',  # Media
            '.exe', '.dll', '.so', '.dylib',  # Binaries
        }
        
        # Common directories to skip
        self.skip_directories = {
            'node_modules', '.git', '__pycache__', '.pytest_cache',
            'venv', '.venv', 'env', '.env', 'build', 'dist',
            '.next', '.nuxt', 'coverage', '.coverage',
        }
    
    def should_skip_file(self, file_path: str) -> bool:
        """
        Determine if a file should be skipped during review.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if file should be skipped
        """
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.skip_extensions:
            return True
        
        # Check if file is in a skip directory
        path_parts = file_path.split('/')
        if any(skip_dir in path_parts for skip_dir in self.skip_directories):
            return True
        
        return False
    
    @abstractmethod
    def analyze_code(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        Analyze code content for issues.
        
        This method must be implemented by each specialized agent.
        
        Args:
            file_path (str): Path to the file being analyzed
            content (str): File content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of findings
        """
        pass
    
    @abstractmethod
    def review_pull_request(self, pr_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Review a pull request with multiple files.
        
        Args:
            pr_files (List[Dict[str, Any]]): List of files to review
            
        Returns:
            Dict[str, Any]: Review results
        """
        pass
    
    def generate_summary_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary report from findings.
        
        Args:
            findings (List[Dict[str, Any]]): List of findings
            
        Returns:
            Dict[str, Any]: Summary report
        """
        if not findings:
            return {
                'status': 'pass',
                'summary': 'No issues detected',
                'total_issues': 0,
                'findings': []
            }
        
        # Count issues by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall status
        critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        status = 'fail' if critical_high > 0 else 'warning'
        
        return {
            'status': status,
            'summary': f"Found {len(findings)} issues",
            'total_issues': len(findings),
            'severity_breakdown': severity_counts,
            'findings': findings
        }