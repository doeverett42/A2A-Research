from __future__ import annotations

import uvicorn

from common.config import config


def main() -> None:
    uvicorn.run(
        "remote.server:app",
        host=config.REMOTE_HOST,
        port=config.REMOTE_PORT,
        reload=False,
    )


if __name__ == "__main__":
    main()
