"""
Multi-Agent Code Review System

This package contains specialized AI agents for code review:
- SecurityReviewAgent: Detects security vulnerabilities
- PerformanceReviewAgent: Analyzes performance issues (coming soon)
- CodeQualityAgent: Reviews code quality and style (coming soon)
- DependencyReviewAgent: Checks dependency security (coming soon)
"""

__version__ = "1.0.0"
__author__ = "Your Name"

from .security_review.agent import SecurityReviewAgent

__all__ = [
    "SecurityReviewAgent",
]