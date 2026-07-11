#Global configuration loader

from __future__ import annotations

import os

from dotenv import load_dotenv


load_dotenv()


def _env_int(name: str) -> int:
    value = os.environ[name]
    return int(value)


def _env_list(name: str) -> list[str]:
    value = os.environ[name]
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def _env_int_list(name: str) -> list[int]:
    return [
        int(value)
        for value in _env_list(name)
    ]


class Config:
    OLLAMA_HOST: str = os.environ["OLLAMA_HOST"]
    HOST_MODEL: str = os.environ["HOST_MODEL"]
    A2A_CLIENT_TIMEOUT_SECONDS: int = _env_int("A2A_CLIENT_TIMEOUT_SECONDS")
    
    REMOTE_AGENT_NAMES: str = os.environ["REMOTE_AGENT_NAMES"]
    REMOTE_AGENT_MODELS: str = os.environ["REMOTE_AGENT_MODELS"]
    REMOTE_AGENT_PORTS: str = os.environ["REMOTE_AGENT_PORTS"]
    REMOTE_HOST: str = os.environ["REMOTE_HOST"]
    REMOTE_AGENT_VERSION: str = os.environ["REMOTE_AGENT_VERSION"]

    @property
    def remote_agent_ports(self) -> list[int]:
        return _env_int_list("REMOTE_AGENT_PORTS")

    @property
    def remote_agent_models(self) -> list[str]:
        return _env_list("REMOTE_AGENT_MODELS")

    @property
    def remote_agent_names(self) -> list[str]:
        return _env_list("REMOTE_AGENT_NAMES")

    @property
    def remote_agent_base_urls(self) -> list[str]:
        return [
            f"http://{self.REMOTE_HOST}:{port}"
            for port in self.remote_agent_ports
        ]

    #import each agents as a list of dictionaries from env for modularity
    @property
    def remote_agent_specs(self) -> list[dict[str, str | int]]:
        if len(self.remote_agent_names) != len(self.remote_agent_models) or len(self.remote_agent_names) != len(self.remote_agent_ports):
            raise ValueError("REMOTE_AGENT_NAMES, REMOTE_AGENT_MODELS, and REMOTE_AGENT_PORTS must have the same length.")

        specs = [
            {
                "index": index,
                "name": name,
                "model": model,
                "port": port
            }
            for index, (name, model, port) in enumerate(
                zip(
                    self.remote_agent_names,
                    self.remote_agent_models,
                    self.remote_agent_ports
                )
            )
        ]
        return specs

    def remote_agent_spec(self, agent_index: int) -> dict[str, str | int]:
        return self.remote_agent_specs[agent_index]

    def remote_base_url(self, port: int) -> str:
        return f"http://{self.REMOTE_HOST}:{port}"

    @property
    def remote_agent_card_urls(self) -> list[str]:
        return self.remote_agent_base_urls


config = Config()