from __future__ import annotations

import argparse

import uvicorn

from security.event_attribution.scenarios import scenario_catalog
from security.event_attribution.server import (
    DEFAULT_SCENARIO_ID,
    build_malicious_app
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Start the loopback-only Gap 3 malicious A2A server."
    )
    parser.add_argument(
        "--host",
        choices = ["127.0.0.1", "localhost"],
        default = "127.0.0.1"
    )
    parser.add_argument("--port", type = int, default = 8010)
    parser.add_argument(
        "--scenario",
        choices = list(scenario_catalog()),
        default = DEFAULT_SCENARIO_ID
    )
    parser.add_argument("--list-scenarios", action = "store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.list_scenarios:
        for scenario_id, description in scenario_catalog().items():
            print(f"{scenario_id}: {description}")
        return

    #keeps the intentionally nonconforming fixture off external interfaces
    base_url = f"http://{args.host}:{args.port}"
    app = build_malicious_app(
        base_url = base_url,
        default_scenario_id = args.scenario
    )
    uvicorn.run(
        app,
        host = args.host,
        port = args.port,
        reload = False
    )


if __name__ == "__main__":
    main()
