from __future__ import annotations

#turns the checked-in sandbox logs into the same small case packets each time

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from cyber.cases import packet_hash


ROOT_DIRECTORY = Path(__file__).resolve().parents[1]
DEFAULT_PACKET_DIRECTORY = ROOT_DIRECTORY / "data" / "cyber_cases" / "packets"
DEFAULT_ANSWER_KEY_DIRECTORY = ROOT_DIRECTORY / "data" / "cyber_cases" / "answer_keys"
SANDBOX_RAW_DIRECTORY = Path(__file__).resolve().parent / "fixtures" / "sandbox_logs"
SANDBOX_DEFINITIONS = Path(__file__).resolve().parent / "fixtures" / "sandbox_cases.json"


def build_cases(
    definition_path: Path,
    raw_directory: Path,
    packet_directory: Path,
    answer_key_directory: Path
) -> list[Path]:
    definitions = json.loads(definition_path.read_text(encoding = "utf-8"))
    if not isinstance(definitions, list):
        raise ValueError("Case definitions must be a JSON list.")

    paths = []
    for definition in definitions:
        paths.append(
            build_case(
                definition,
                raw_directory,
                packet_directory,
                answer_key_directory
            )
        )
    return paths


def build_case(
    definition: dict,
    raw_directory: Path,
    packet_directory: Path,
    answer_key_directory: Path
) -> Path:
    case_label = str(definition["case_label"]).upper()
    time_window = dict(definition["time_window"])
    start = _parse_time(str(time_window["start"]))
    end = _parse_time(str(time_window["end"]))
    if end < start:
        raise ValueError(f"{case_label} ends before it starts.")

    limit = int(definition.get("limit_per_group", 12))
    if limit < 1:
        raise ValueError("limit_per_group must be positive.")

    evidence_groups = {}
    for group_name, source_specs in definition["groups"].items():
        records = []
        for source_spec in source_specs:
            source_path = raw_directory / str(source_spec["file"])
            if not source_path.exists():
                raise FileNotFoundError(
                    f"Missing source for {case_label}: {source_path}"
                )
            records.extend(
                _source_records(
                    source_path,
                    source_spec,
                    start,
                    end
                )
            )
        records.sort(
            key = lambda item: (
                item["timestamp"],
                item["source"],
                item["event"]
            )
        )
        evidence_groups[group_name] = _number_records(records[:limit])

    missing_groups = [
        name
        for name, records in evidence_groups.items()
        if not records
    ]
    if missing_groups:
        raise ValueError(
            f"{case_label} produced no evidence for: {', '.join(missing_groups)}"
        )

    packet = {
        "case_label": case_label,
        "title": str(definition["title"]),
        "dataset": str(definition["dataset"]),
        "time_window": time_window,
        "selection_rule": str(definition["selection_rule"]),
        "evidence_groups": evidence_groups
    }
    packet["packet_hash"] = packet_hash(packet)

    packet_directory.mkdir(parents = True, exist_ok = True)
    packet_path = packet_directory / f"{case_label.lower()}.json"
    _write_json(packet_path, packet)

    answer_key = {
        "case_label": case_label,
        "packet_hash": packet["packet_hash"],
        "notes": definition.get("answer_key", {})
    }
    answer_key_directory.mkdir(parents = True, exist_ok = True)
    _write_json(
        answer_key_directory / f"{case_label.lower()}.answer.json",
        answer_key
    )
    return packet_path


def _source_records(
    path: Path,
    source_spec: dict,
    start: datetime,
    end: datetime
) -> list[dict]:
    records = []
    terms = [
        str(term).lower()
        for term in source_spec.get("contains_any", [])
    ]
    with path.open("r", encoding = "utf-8-sig", errors = "replace", newline = "") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            timestamp = _row_time(row)
            if timestamp is None or timestamp < start or timestamp > end:
                continue
            searchable = json.dumps(row, ensure_ascii = False).lower()
            if terms and not any(term in searchable for term in terms):
                continue
            records.append(
                {
                    "prefix": str(source_spec["prefix"]),
                    "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                    "source": str(source_spec["sourcetype"]),
                    "event": _event_text(row)
                }
            )
    return records


def _number_records(records: list[dict]) -> list[dict]:
    prefix_counts = {}
    numbered = []
    for record in records:
        prefix = record.pop("prefix")
        prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
        numbered.append(
            {
                "evidence_id": f"{prefix}-{prefix_counts[prefix]:03d}",
                **record
            }
        )
    return numbered


def _row_time(row: dict[str, str]) -> datetime | None:
    for key in ("_time", "timestamp", "time", "date"):
        value = str(row.get(key, "")).strip()
        if not value:
            continue
        try:
            if value.replace(".", "", 1).isdigit():
                return datetime.fromtimestamp(float(value), tz = timezone.utc)
            return _parse_time(value)
        except ValueError:
            continue
    return None


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo = timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_text(row: dict[str, str]) -> str:
    raw = str(row.get("_raw", "")).strip()
    if raw:
        text = raw
    else:
        fields = [
            f"{key}={value}"
            for key, value in row.items()
            if key != "_time" and str(value).strip()
        ]
        text = " ".join(fields)
    return " ".join(text.split())[:800]


def _write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent = 2, ensure_ascii = False) + "\n",
        encoding = "utf-8"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Rebuild the fixed sandbox case packets from local CSV logs."
    )
    parser.add_argument("command", choices = ["build-sandbox"])
    return parser.parse_args()


def main() -> None:
    _parse_args()
    paths = build_cases(
        SANDBOX_DEFINITIONS,
        SANDBOX_RAW_DIRECTORY,
        DEFAULT_PACKET_DIRECTORY,
        DEFAULT_ANSWER_KEY_DIRECTORY
    )
    for path in paths:
        print(f"built {path}")


if __name__ == "__main__":
    main()
