from __future__ import annotations

from sqlalchemy import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from a2a.server.tasks import DatabaseTaskStore

from common.config import config


def build_task_store(
    agent_index: int
) -> tuple[DatabaseTaskStore, AsyncEngine]:
    database_path = config.remote_task_database_path(agent_index)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = URL.create(
        drivername = "sqlite+aiosqlite",
        database = str(database_path)
    )
    database_engine = create_async_engine(database_url)
    task_store = DatabaseTaskStore(engine=database_engine)
    return task_store, database_engine
