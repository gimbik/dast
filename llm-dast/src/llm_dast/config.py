from pathlib import Path
from pydantic import BaseModel, Field
import yaml
import os

class ZAPScanConfig(BaseModel):
    spider: bool = True
    ajax_spider: bool = False
    active_scan: bool = True
    max_duration_minutes: int = 5

class ZAPConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    api_key: str = ""
    scan: ZAPScanConfig = Field(default_factory=ZAPScanConfig)

class AuthConfig(BaseModel):
    enabled: bool = False
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    logged_in_indicator: str = ""

class LLMConfig(BaseModel):
    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    temperature: float = 0.1
    json_mode: bool = True

class AppConfig(BaseModel):
    target: dict
    zap: ZAPConfig
    llm: LLMConfig
    auth: AuthConfig = Field(default_factory=AuthConfig) # ДОБАВИЛИ

def load_config(config_path: str = "config/default.yaml") -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found at {config_path}")
    
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
        
    return AppConfig(**raw)