# Global configuration loader

from __future__ import annotations

import os

from dotenv import load_dotenv


load_dotenv()


def _env_int(name: str) -> int:
    value = os.getenv(name)
    try:
        return int(value)
    except ValueError as e:
        raise ValueError(f"{name} must be an integer, got {value!r}") from e

class Config:
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST")
    HOST_MODEL: str = os.getenv("HOST_MODEL")
    
    REMOTE_MODEL: str = os.getenv("REMOTE_MODEL")
    REMOTE_HOST: str = os.getenv("REMOTE_HOST")
    REMOTE_PORT: int = _env_int("REMOTE_PORT")
    REMOTE_AGENT_NAME: str = os.getenv("REMOTE_AGENT_NAME")
    REMOTE_AGENT_VERSION: str = os.getenv("REMOTE_AGENT_VERSION")

    @property
    def remote_base_url(self) -> str:
        return f"http://{self.REMOTE_HOST}:{self.REMOTE_PORT}"


config = Config()
