from __future__ import annotations

from starlette.applications import Starlette

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore

from remote.executor import RemoteAgentExecutor


def build_remote_app(agent_card, executor: RemoteAgentExecutor) -> Starlette:
    request_handler = DefaultRequestHandler(
        agent_executor = executor,
        task_store = InMemoryTaskStore(),
        agent_card = agent_card,
    )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(request_handler, "/"))
    return Starlette(routes=routes)
