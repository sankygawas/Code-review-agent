"""
Security Review Agent

Specialized agent for detecting security vulnerabilities in code including:
- Exposed secrets (API keys, passwords, tokens)
- Injection vulnerabilities (SQL, Command, XSS)
- Authentication and authorization flaws
- Input validation issues
- Cryptographic weaknesses
"""

from .agent import SecurityReviewAgent

__all__ = ["SecurityReviewAgent"]