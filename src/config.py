"""
SentinelRAG - Centralized Configuration

All environment variables are loaded here to provide a single source of truth.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""
    
    # LLM Configuration
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.synthetic.new/openai/v1")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "llama3.2")
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "hf:nomic-ai/nomic-embed-text-v1.5")
    EMBEDDING_DIMENSIONS: int = 768  # nomic-embed-text-v1.5 output size
    
    # Database
    NEON_DATABASE_URL: str = os.getenv("NEON_DATABASE_URL", "")
    
    # LangSmith Observability
    LANGSMITH_API_KEY: str = os.getenv("LANGSMITH_API_KEY", "")
    LANGSMITH_PROJECT: str = os.getenv("LANGSMITH_PROJECT", "SentinelRAG")
    
    # NVD API
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # App Security
    APP_PASSWORD: str = os.getenv("APP_PASSWORD", "")
    
    # Rate limiting (requests per 30 seconds)
    NVD_RATE_LIMIT: int = 50 if os.getenv("NVD_API_KEY") else 5
    
    @classmethod
    def validate(cls) -> list[str]:
        """Validate required configuration. Returns list of missing variables."""
        missing = []
        if not cls.OPENAI_API_KEY:
            missing.append("OPENAI_API_KEY")
        if not cls.NEON_DATABASE_URL:
            missing.append("NEON_DATABASE_URL")
        return missing


# Singleton instance
config = Config()
