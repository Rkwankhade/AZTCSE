# AZTCSE Configuration
# Autonomous Zero-Trust Cloud Security Engine
# IIIT Nagpur - Advanced Cloud Security Project

import os
from pydantic_settings import BaseSettings
from typing import Optional

class AZTCSEConfig(BaseSettings):
    # ─── Application ──────────────────────────────────────────────
    APP_NAME: str = "AZTCSE - Autonomous Zero-Trust Cloud Security Engine"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = os.getenv("SECRET_KEY", "aztcse-iiit-nagpur-2024-change-in-prod")
    
    # ─── Server ───────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    
    # ─── Neo4j (Attack Graph DB) ──────────────────────────────────
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "aztcse_secure_pass")
    
    # ─── Redis (Real-time cache) ──────────────────────────────────
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # ─── AWS Cloud Credentials ────────────────────────────────────
    AWS_ACCESS_KEY_ID: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_ACCOUNT_ID: Optional[str] = os.getenv("AWS_ACCOUNT_ID")
    
    # ─── AI/ML Settings ───────────────────────────────────────────
    RL_LEARNING_RATE: float = 0.0003
    RL_EPISODES: int = 1000
    GNN_HIDDEN_DIM: int = 128
    GNN_LAYERS: int = 4
    RISK_THRESHOLD_CRITICAL: float = 0.85
    RISK_THRESHOLD_HIGH: float = 0.65
    RISK_THRESHOLD_MEDIUM: float = 0.40
    
    # ─── Response Engine ──────────────────────────────────────────
    AUTO_RESPONSE_ENABLED: bool = True
    RESPONSE_TIMEOUT_SECONDS: int = 30
    MAX_AUTO_ACTIONS_PER_HOUR: int = 100
    HUMAN_APPROVAL_THRESHOLD: float = 0.95  # Above this risk, require human
    
    # ─── Zero Trust ───────────────────────────────────────────────
    JIT_ACCESS_DURATION_MINUTES: int = 60
    SESSION_REVALIDATION_INTERVAL: int = 300  # seconds
    
    # ─── Monitoring ───────────────────────────────────────────────
    METRICS_PORT: int = 9090
    LOG_LEVEL: str = "INFO"
    ALERT_WEBHOOK_URL: Optional[str] = os.getenv("ALERT_WEBHOOK_URL")
    
    # ─── Digital Twin ─────────────────────────────────────────────
    TWIN_SYNC_INTERVAL: int = 60  # seconds
    TWIN_SIMULATION_THREADS: int = 8
    
    class Config:
        env_file = ".env"
        case_sensitive = True

config = AZTCSEConfig()
