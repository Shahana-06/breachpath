import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    GITHUB_ORG = os.getenv("GITHUB_ORG", "")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "")
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
    NEO4J_URI = os.getenv("NEO4J_URI", "")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", "7"))
    CRITICAL_KEYWORDS = [k.strip() for k in os.getenv("CRITICAL_KEYWORDS", "prod,production,payment,backup").split(",") if k.strip()]


settings = Settings()
