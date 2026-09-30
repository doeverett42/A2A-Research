from __future__ import annotations

#builds one configured agent app for the cli and both local service launchers

from common.config import config
from common.ollama_client import OllamaClient
from cyber.cases import CyberCaseStore
from remote.agent import OllamaRemoteAgent
from remote.agent_card import build_agent_card
from remote.case_evidence import CaseEvidenceStore
from remote.executor import RemoteAgentExecutor
from remote.server import build_remote_app
from remote.task_store import build_task_store


def build_configured_remote_app(agent_index: int):
    spec = config.remote_agent_spec(agent_index)
    port = int(spec["port"])
    task_store, database_engine = build_task_store(agent_index)
    app = build_remote_app(
        agent_card = build_agent_card(
            agent_spec = spec,
            version = config.REMOTE_AGENT_VERSION,
            base_url = config.remote_base_url(port)
        ),
        executor = RemoteAgentExecutor(
            OllamaRemoteAgent(
                client = OllamaClient(config.OLLAMA_HOST),
                model = str(spec["model"]),
                system_prompt = str(spec["system_prompt"])
            ),
            case_evidence_store = CaseEvidenceStore(
                database_engine,
                str(spec["name"]),
                CyberCaseStore(config.cyber_case_directory_path)
            )
        ),
        task_store = task_store,
        database_engine = database_engine
    )
    return app, spec

