from typing import List, Optional
from pydantic import BaseModel, Field, HttpUrl
import json
import logging

logger = logging.getLogger(__name__)

class ProxyProvider(BaseModel):
    type: int = Field(..., description="Proxy type: 1 for HTTP, 4 for SOCKS4, 5 for SOCKS5")
    url: HttpUrl
    timeout: int = Field(default=5, ge=1, le=120)

class AppConfig(BaseModel):
    MCBOT: str = Field(default="MHcheck_")
    MINECRAFT_DEFAULT_PROTOCOL: int = Field(default=47)
    proxy_providers: List[ProxyProvider] = Field(alias="proxy-providers", default_factory=list)
    shodan_api_key: str = Field(default="")
    
class PresetConfig(BaseModel):
    name: str = Field(..., description="Name of the preset")
    target: str = Field(..., description="Target IP or Domain")
    port: int = Field(default=80, ge=1, le=65535)
    method: str = Field(..., description="Attack method or OSINT method name")
    duration: int = Field(default=60, ge=1, description="Duration in seconds")
    threads: int = Field(default=10, ge=1, description="Number of threads")
    kwargs: dict = Field(default_factory=dict, description="Arbitrary arguments for the method")

def load_config(filepath: str = "config.json") -> Optional[AppConfig]:
    """Loads and validates the main application config."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        config = AppConfig(**data)
        logger.info(f"Loaded configuration successfully from {filepath}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {filepath} not found.")
        return None
    except Exception as e:
        logger.error(f"Configuration validation error: {e}")
        return None

def load_preset(filepath: str) -> Optional[PresetConfig]:
    """Loads and validates a test preset."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        preset = PresetConfig(**data)
        logger.info(f"Loaded preset successfully from {filepath}")
        return preset
    except Exception as e:
        logger.error(f"Preset validation error in {filepath}: {e}")
        return None
