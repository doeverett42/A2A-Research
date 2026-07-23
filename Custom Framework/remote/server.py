from __future__ import annotations

from contextlib import asynccontextmanager

from starlette.applications import Starlette
from sqlalchemy.ext.asyncio import AsyncEngine

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import DatabaseTaskStore

from common.audit import AuditMiddleware
from remote.executor import RemoteAgentExecutor


def build_remote_app(
    agent_card,
    executor: RemoteAgentExecutor,
    task_store: DatabaseTaskStore,
    database_engine: AsyncEngine
) -> Starlette:
    @asynccontextmanager
    async def lifespan(app: Starlette):
        await task_store.initialize()
        try:
            yield
        finally:
            await database_engine.dispose()

    request_handler = DefaultRequestHandler(
        agent_executor = executor,
        task_store = task_store,
        agent_card = agent_card
    )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(request_handler, "/"))
    app = Starlette(routes=routes, lifespan=lifespan)

    #records requests carrying the security test audit header
    app.add_middleware(
        AuditMiddleware,
        agent_name = agent_card.name
    )
    return app
