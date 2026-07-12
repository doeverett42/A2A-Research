#Global configuration loader

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv


load_dotenv()


def _env_int(name: str) -> int:
    value = os.environ[name]
    return int(value)


def _env_list(name: str, delimiter: str = ",") -> list[str]:
    value = os.environ[name]
    return [item.strip() for item in value.split(delimiter) if item.strip()]


def _env_int_list(name: str) -> list[int]:
    return [int(value) for value in _env_list(name)]


def _env_pipe_list(name: str) -> list[str]:
    return _env_list(name, "|")


def _env_semicolon_lists(name: str) -> list[list[str]]:
    return [
        [
            value.strip() for value in item.split(";") if value.strip()
        ]
        for item in _env_pipe_list(name)
    ]


class Config:
    OLLAMA_HOST: str = os.environ["OLLAMA_HOST"]
    HOST_MODEL: str = os.environ["HOST_MODEL"]
    A2A_CLIENT_TIMEOUT_SECONDS: int = _env_int("A2A_CLIENT_TIMEOUT_SECONDS")
    
    REMOTE_AGENT_NAMES: str = os.environ["REMOTE_AGENT_NAMES"]
    REMOTE_AGENT_MODELS: str = os.environ["REMOTE_AGENT_MODELS"]
    REMOTE_AGENT_PORTS: str = os.environ["REMOTE_AGENT_PORTS"]
    REMOTE_AGENT_CARD_DESCRIPTIONS: str = os.environ["REMOTE_AGENT_CARD_DESCRIPTIONS"]
    REMOTE_AGENT_SKILL_IDS: str = os.environ["REMOTE_AGENT_SKILL_IDS"]
    REMOTE_AGENT_SKILL_NAMES: str = os.environ["REMOTE_AGENT_SKILL_NAMES"]
    REMOTE_AGENT_SKILL_DESCRIPTIONS: str = os.environ["REMOTE_AGENT_SKILL_DESCRIPTIONS"]
    REMOTE_AGENT_SKILL_TAGS: str = os.environ["REMOTE_AGENT_SKILL_TAGS"]
    REMOTE_AGENT_SKILL_EXAMPLES: str = os.environ["REMOTE_AGENT_SKILL_EXAMPLES"]
    REMOTE_AGENT_SYSTEM_PROMPTS: str = os.environ["REMOTE_AGENT_SYSTEM_PROMPTS"]
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
    def remote_agent_card_descriptions(self) -> list[str]:
        return _env_pipe_list("REMOTE_AGENT_CARD_DESCRIPTIONS")

    @property
    def remote_agent_skill_ids(self) -> list[str]:
        return _env_list("REMOTE_AGENT_SKILL_IDS")

    @property
    def remote_agent_skill_names(self) -> list[str]:
        return _env_list("REMOTE_AGENT_SKILL_NAMES")

    @property
    def remote_agent_skill_descriptions(self) -> list[str]:
        return _env_pipe_list("REMOTE_AGENT_SKILL_DESCRIPTIONS")

    @property
    def remote_agent_skill_tags(self) -> list[list[str]]:
        return _env_semicolon_lists("REMOTE_AGENT_SKILL_TAGS")

    @property
    def remote_agent_skill_examples(self) -> list[list[str]]:
        return _env_semicolon_lists("REMOTE_AGENT_SKILL_EXAMPLES")

    @property
    def remote_agent_system_prompts(self) -> list[str]:
        return _env_pipe_list("REMOTE_AGENT_SYSTEM_PROMPTS")

    @property
    def remote_agent_base_urls(self) -> list[str]:
        return [f"http://{self.REMOTE_HOST}:{port}" for port in self.remote_agent_ports]

    #import each agents as a list of dictionaries from env for modularity
    @property
    def remote_agent_specs(self) -> list[dict[str, Any]]:
        names = self.remote_agent_names
        models = self.remote_agent_models
        ports = self.remote_agent_ports
        card_descriptions = self.remote_agent_card_descriptions
        skill_ids = self.remote_agent_skill_ids
        skill_names = self.remote_agent_skill_names
        skill_descriptions = self.remote_agent_skill_descriptions
        skill_tags = self.remote_agent_skill_tags
        skill_examples = self.remote_agent_skill_examples
        system_prompts = self.remote_agent_system_prompts

        agent_config_lists = [
            ("REMOTE_AGENT_MODELS", models),
            ("REMOTE_AGENT_PORTS", ports),
            ("REMOTE_AGENT_CARD_DESCRIPTIONS", card_descriptions),
            ("REMOTE_AGENT_SKILL_IDS", skill_ids),
            ("REMOTE_AGENT_SKILL_NAMES", skill_names),
            ("REMOTE_AGENT_SKILL_DESCRIPTIONS", skill_descriptions),
            ("REMOTE_AGENT_SKILL_TAGS", skill_tags),
            ("REMOTE_AGENT_SKILL_EXAMPLES", skill_examples),
            ("REMOTE_AGENT_SYSTEM_PROMPTS", system_prompts)
        ]
        for name, values in agent_config_lists:
            if len(values) != len(names):
                raise ValueError(f"REMOTE_AGENT_NAMES and {name} must have the same length.")

        specs = [
            {
                "index": index,
                "name": name,
                "model": model,
                "port": port,
                "card_description": card_description,
                "skill": {
                    "id": skill_id,
                    "name": skill_name,
                    "description": skill_description,
                    "tags": tags,
                    "examples": examples
                },
                "system_prompt": system_prompt
            }
            for index, (
                name,
                model,
                port,
                card_description,
                skill_id,
                skill_name,
                skill_description,
                tags,
                examples,
                system_prompt
            ) in enumerate(
                zip(
                    names,
                    models,
                    ports,
                    card_descriptions,
                    skill_ids,
                    skill_names,
                    skill_descriptions,
                    skill_tags,
                    skill_examples,
                    system_prompts
                )
            )
        ]
        return specs

    def remote_agent_spec(self, agent_index: int) -> dict[str, Any]:
        return self.remote_agent_specs[agent_index]

    def remote_base_url(self, port: int) -> str:
        return f"http://{self.REMOTE_HOST}:{port}"

    @property
    def remote_agent_card_urls(self) -> list[str]:
        return self.remote_agent_base_urls


config = Config()
