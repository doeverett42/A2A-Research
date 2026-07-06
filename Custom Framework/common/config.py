# Global configuration loader

from __future__ import annotations

import os

from dotenv import load_dotenv


load_dotenv()


def _env_int(name: str, default: int | None = None) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        if default is not None:
            return default
        raise ValueError(f"{name} must be set")
    try:
        return int(value)
    except ValueError as e:
        raise ValueError(f"{name} must be an integer, got {value!r}") from e

class Config:
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST")
    HOST_MODEL: str = os.getenv("HOST_MODEL")
    HOST_REMOTE_URL: str = os.getenv("HOST_REMOTE_URL")
    A2A_CLIENT_TIMEOUT_SECONDS: int = _env_int("A2A_CLIENT_TIMEOUT_SECONDS", 300)
    
    REMOTE_MODEL: str = os.getenv("REMOTE_MODEL")
    REMOTE_HOST: str = os.getenv("REMOTE_HOST")
    REMOTE_PORT: int = _env_int("REMOTE_PORT", 8001)
    REMOTE_AGENT_NAME: str = os.getenv("REMOTE_AGENT_NAME")
    REMOTE_AGENT_VERSION: str = os.getenv("REMOTE_AGENT_VERSION")

    @property
    def remote_base_url(self) -> str:
        return f"http://{self.REMOTE_HOST}:{self.REMOTE_PORT}"

    @property
    def host_remote_url(self) -> str:
        return self.HOST_REMOTE_URL or self.remote_base_url

    def ollama_model(self, model: str | None) -> str:
        if model and model.startswith("ollama:"):
            return model.removeprefix("ollama:")
        return model


config = Config()
