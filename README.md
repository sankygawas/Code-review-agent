# Multi-Agent Code Review System

A comprehensive code review system built with [Agno](https://github.com/agno-agi/agno) that uses specialized AI agents to analyze pull requests for security vulnerabilities, performance issues, code quality, and more.

## 🚀 Features

- **Security Review Agent**: Detects exposed secrets, SQL injection, XSS, command injection vulnerabilities
- **GitHub-Style Comments**: Provides exact line-by-line feedback with severity indicators
- **Extensible Architecture**: Easy to add new specialized review agents
- **Multi-Model Support**: Works with OpenAI, Anthropic, OpenRouter, and 20+ other providers
- **Comprehensive Reporting**: Detailed analysis with actionable recommendations

## 📋 Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- API key for your chosen model provider (OpenAI, Anthropic, OpenRouter, etc.)

## 🛠️ Installation

### 1. Install uv (if not already installed)

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via Homebrew (macOS)
brew install uv

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Clone the Repository

```bash
git clone <your-repo-url>
cd Code-review-agent
```

### 3. Setup Virtual Environment

```bash
# Create virtual environment with Python 3.12
uv venv --python 3.12

# Activate virtual environment
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows
```

### 4. Install Dependencies

```bash
uv pip install agno anthropic openai yfinance
```

## 🔑 API Configuration

### Option 1: OpenAI (Recommended)

1. Get your API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Set environment variable:

```bash
export OPENAI_API_KEY="sk-proj-your-api-key-here"
```

### Option 2: OpenRouter (Cost-Effective Alternative)

OpenRouter provides access to multiple models at competitive prices.

1. Sign up at [OpenRouter](https://openrouter.ai/)
2. Get your API key from the dashboard
3. Set environment variable:

```bash
export OPENROUTER_API_KEY="sk-or-your-api-key-here"
```

4. Update the agent to use OpenRouter:

```python
from agno.models.openrouter import OpenRouterChat

agent = SecurityReviewAgent(
    model=OpenRouterChat(
        id="anthropic/claude-3.5-sonnet",  # or any OpenRouter model
        api_key=os.getenv("OPENROUTER_API_KEY")
    )
)
```

### Option 3: Anthropic Claude

1. Get your API key from [Anthropic Console](https://console.anthropic.com/)
2. Set environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-your-api-key-here"
```

## 🚦 Quick Start

### Running the Security Review Agent

```bash
# Activate virtual environment
source .venv/bin/activate

# Set your API key
export OPENAI_API_KEY="your-api-key-here"

# Run the example
python agents/security_review/example_usage.py
```

### Expected Output

The agent will analyze vulnerable code samples and provide GitHub-style security comments:

```markdown
## 🚨 Security Issue - CRITICAL

**File:** `src/database.py` (Line 6)

**Issue:** Potential password exposed in code

**Code:**
```python
DB_PASSWORD = "admin123"
```

**Recommendation:** Move password to environment variables or secure vault
```

## 📁 Project Structure

```
Code-review-agent/
├── README.md
├── requirements.txt
├── .env.example
├── agents/
│   ├── __init__.py
│   ├── security_review/
│   │   ├── __init__.py
│   │   ├── agent.py
│   │   └── example_usage.py
│   ├── performance_review/     # Future agent
│   ├── code_quality/          # Future agent
│   └── dependency_review/     # Future agent
├── core/
│   ├── __init__.py
│   ├── base_agent.py
│   └── report_generator.py
├── utils/
│   ├── __init__.py
│   ├── github_integration.py
│   └── file_analyzer.py
└── examples/
    └── vulnerable_code_samples/
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Model Configuration
OPENAI_API_KEY=sk-proj-your-key-here
# ANTHROPIC_API_KEY=sk-ant-your-key-here
# OPENROUTER_API_KEY=sk-or-your-key-here

# Agent Settings
DEBUG_MODE=true
MODEL_PROVIDER=openai
DEFAULT_MODEL=gpt-4o

# GitHub Integration (Optional)
GITHUB_TOKEN=ghp_your-token-here
GITHUB_WEBHOOK_SECRET=your-webhook-secret
```

### Model Selection

The system supports multiple model providers:

```python
# OpenAI
from agno.models.openai import OpenAIChat
model = OpenAIChat(id="gpt-4o")

# Anthropic
from agno.models.anthropic import AnthropicChat  
model = AnthropicChat(id="claude-3-5-sonnet-20241022")

# OpenRouter (Multiple providers)
from agno.models.openrouter import OpenRouterChat
model = OpenRouterChat(id="anthropic/claude-3.5-sonnet")
```

## 🎯 Usage Examples

### Basic Security Review

```python
from agents.security_review.agent import SecurityReviewAgent

# Initialize agent
agent = SecurityReviewAgent()

# Review code files
files = [
    {
        'filename': 'src/auth.py',
        'content': open('src/auth.py').read()
    }
]

# Get security analysis
result = agent.review_pull_request(files)
print(f"Status: {result['status']}")
print(f"Issues found: {result['total_issues']}")
```

### GitHub Integration

```python
from utils.github_integration import GitHubReviewer

reviewer = GitHubReviewer(
    agent=SecurityReviewAgent(),
    github_token=os.getenv("GITHUB_TOKEN")
)

# Review a pull request
reviewer.review_pr(
    repo="owner/repository",
    pr_number=123
)
```

## 🔍 Security Vulnerabilities Detected

The Security Review Agent detects:

- **Exposed Secrets**: API keys, passwords, tokens, private keys
- **Injection Vulnerabilities**: SQL injection, command injection, XSS
- **Authentication Issues**: Weak hashing, insecure sessions
- **Input Validation**: Unvalidated user inputs
- **Cryptographic Weaknesses**: Weak algorithms, insecure random generation

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
uv pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=agents --cov-report=html
```

## 📊 Adding New Agents

### 1. Create Agent Directory

```bash
mkdir agents/your_new_agent
touch agents/your_new_agent/__init__.py
touch agents/your_new_agent/agent.py
touch agents/your_new_agent/example_usage.py
```

### 2. Implement Agent

```python
# agents/your_new_agent/agent.py
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from core.base_agent import BaseReviewAgent

class YourNewAgent(BaseReviewAgent):
    def __init__(self):
        super().__init__(
            model=OpenAIChat(id="gpt-4o"),
            name="Your New Agent",
            instructions=[
                "Your agent instructions here",
            ]
        )
    
    def analyze_code(self, file_path: str, content: str):
        # Your analysis logic here
        pass
```

### 3. Add Example Usage

```python
# agents/your_new_agent/example_usage.py
from .agent import YourNewAgent

def demo():
    agent = YourNewAgent()
    # Demo code here

if __name__ == "__main__":
    demo()
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-agent`)
3. Commit your changes (`git commit -am 'Add new agent'`)
4. Push to the branch (`git push origin feature/new-agent`)
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Agno Framework](https://github.com/agno-agi/agno) - The multi-agent framework powering this system
- [OpenAI](https://openai.com/) - GPT models for code analysis
- [Anthropic](https://anthropic.com/) - Claude models for advanced reasoning
- [OpenRouter](https://openrouter.ai/) - Multi-model API access

## 📧 Support

For questions and support:
- Open an issue on GitHub
- Check the [Agno Documentation](https://docs.agno.ai/)
- Join the community discussions

---

**Note**: This is a tutorial project for educational purposes. Always review and test the agent's recommendations before implementing them in production code.