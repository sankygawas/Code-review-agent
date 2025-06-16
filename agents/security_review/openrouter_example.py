#!/usr/bin/env python3
"""
Security Review Agent with OpenRouter Integration

Example showing how to use the Security Review Agent with OpenRouter for
cost-effective access to multiple AI models including Claude, GPT-4, and others.

OpenRouter provides:
- Competitive pricing across models
- Access to latest models from multiple providers
- Simple API compatible with OpenAI format
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the parent directory to Python path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agno.agent import Agent
from agno.models.openai import OpenAIChat  # OpenRouter uses OpenAI-compatible API


class SecurityReviewAgentOpenRouter(Agent):
    """
    Security Review Agent configured for OpenRouter.
    
    OpenRouter provides access to multiple AI models through a single API,
    offering competitive pricing and access to the latest models.
    """
    
    def __init__(self, model_id: str = "anthropic/claude-3.5-sonnet", debug: bool = True):
        """
        Initialize Security Review Agent with OpenRouter.
        
        Popular OpenRouter models:
        - anthropic/claude-3.5-sonnet (recommended for code analysis)
        - openai/gpt-4o (good balance of speed and quality)
        - openai/gpt-4o-mini (fast and cost-effective)
        - google/gemini-pro (good for complex analysis)
        - meta-llama/llama-3.1-8b-instruct (open source option)
        
        Args:
            model_id (str): OpenRouter model ID
            debug (bool): Enable debug mode
        """
        # Configure OpenAI client to use OpenRouter
        openai_model = OpenAIChat(
            id=model_id,
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            # OpenRouter specific headers
            extra_headers={
                "HTTP-Referer": "https://github.com/your-repo",  # Optional
                "X-Title": "Security Review Agent"  # Optional
            }
        )
        
        super().__init__(
            model=openai_model,
            name="Security Review Agent (OpenRouter)",
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
                "Be thorough but avoid false positives.",
                "Format your responses in GitHub-style markdown comments."
            ],
            markdown=True,
            debug_mode=debug
        )
    
    def analyze_file(self, file_path: str, content: str) -> str:
        """
        Analyze a single file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the file
            content (str): File content
            
        Returns:
            str: Security analysis report
        """
        prompt = f"""
        Analyze the following code file for security vulnerabilities:
        
        **File:** {file_path}
        
        **Code:**
        ```python
        {content}
        ```
        
        Please identify any security issues and provide:
        1. Severity level (Critical/High/Medium/Low)
        2. Vulnerability type
        3. Line number(s) where issues occur
        4. Specific recommendations for fixing each issue
        5. Example of secure code where applicable
        
        Format your response as GitHub-style comments with clear actionable advice.
        """
        
        response = self.run(prompt)
        return response.content


def demo_openrouter_security_review():
    """Demonstrate Security Review Agent with OpenRouter"""
    
    # Check if OpenRouter API key is set
    if not os.getenv("OPENROUTER_API_KEY"):
        print("❌ OPENROUTER_API_KEY environment variable not set!")
        print("Please set your OpenRouter API key:")
        print("export OPENROUTER_API_KEY='sk-or-your-api-key-here'")
        return
    
    print("🔍 Security Review Agent with OpenRouter")
    print("=" * 50)
    print(f"Using model: anthropic/claude-3.5-sonnet")
    print("API: OpenRouter (https://openrouter.ai/)")
    print()
    
    # Initialize agent
    agent = SecurityReviewAgentOpenRouter(
        model_id="anthropic/claude-3.5-sonnet",  # High-quality model for security analysis
        debug=True
    )
    
    # Load example vulnerable code
    examples_dir = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "vulnerable_code_samples")
    
    files_to_analyze = [
        "database.py",
        "web_handler.py"
    ]
    
    for filename in files_to_analyze:
        file_path = os.path.join(examples_dir, filename)
        
        if os.path.exists(file_path):
            print(f"📁 Analyzing: {filename}")
            print("-" * 30)
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Analyze the file
            analysis = agent.analyze_file(filename, content)
            print(analysis)
            print("\n" + "="*80 + "\n")
        else:
            print(f"⚠️  File not found: {file_path}")
    
    print("✅ Security analysis complete!")
    print("\n💡 OpenRouter Benefits:")
    print("- Access to multiple AI models")
    print("- Competitive pricing")
    print("- Latest model versions")
    print("- No vendor lock-in")


if __name__ == "__main__":
    demo_openrouter_security_review()