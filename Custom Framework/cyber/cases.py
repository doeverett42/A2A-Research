from __future__ import annotations

#loads one fixed case packet and gives each agent only its assigned evidence

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


AGENT_EVIDENCE_GROUPS = {
    "Identity Analyst": "identity",
    "Endpoint Analyst": "endpoint",
    "Network Analyst": "network",
    "Web and DNS Analyst": "web_dns",
    "Incident Correlation Analyst": "alerts"
}
CASE_LABEL_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
CASE_BLOCK_PATTERN = re.compile(
    r"\[local-case\]\s*"
    r"case_label:\s*(?P<case_label>[A-Z0-9-]+)\s*"
    r"packet_hash:\s*(?P<packet_hash>[a-f0-9]{64})\s*"
    r"evidence_group:\s*(?P<evidence_group>[a-z_]+)\s*"
    r"\[/local-case\]",
    re.IGNORECASE
)


@dataclass(frozen = True)
class CaseMetadata:
    case_label: str
    packet_hash: str
    evidence_group: str


@dataclass(frozen = True)
class CasePacket:
    data: dict

    @property
    def case_label(self) -> str:
        return str(self.data["case_label"])

    @property
    def packet_hash(self) -> str:
        return str(self.data["packet_hash"])

    @property
    def title(self) -> str:
        return str(self.data["title"])

    @property
    def evidence_groups(self) -> dict[str, list[dict]]:
        return dict(self.data["evidence_groups"])


@dataclass(frozen = True)
class CaseContext:
    packet: CasePacket


class CyberCaseStore:
    def __init__(self, packet_directory: Path) -> None:
        self.packet_directory = packet_directory.resolve()
        self._packets = self._load_packets()

    def labels(self) -> list[str]:
        return sorted(self._packets)

    def get(self, case_label: str) -> CasePacket:
        try:
            return self._packets[case_label.upper()]
        except KeyError as e:
            raise ValueError(f"Unknown local cyber case: {case_label}") from e

    def resolve(self, user_message: str) -> CaseContext | None:
        upper_message = user_message.upper()
        matches = []
        for case_label in sorted(self._packets, key = len, reverse = True):
            pattern = rf"(?<![A-Z0-9-]){re.escape(case_label)}(?![A-Z0-9-])"
            if re.search(pattern, upper_message):
                matches.append(case_label)

        if len(matches) > 1:
            raise ValueError(
                "Use one local cyber case per request. Found: "
                + ", ".join(matches)
            )
        if matches:
            return CaseContext(self._packets[matches[0]])
        return None

    def planning_message(self, user_message: str, context: CaseContext) -> str:
        packet = context.packet
        groups = ", ".join(sorted(packet.evidence_groups))
        return "\n".join(
            [
                user_message.strip(),
                "",
                f"Selected local case: {packet.case_label}",
                f"Case title: {packet.title}",
                f"Available evidence groups: {groups}",
                "The host will attach each evidence group only to its matching specialist."
            ]
        )

    def delegation_message(
        self,
        user_message: str,
        context: CaseContext,
        agent_name: str
    ) -> str:
        packet = context.packet
        evidence_group = AGENT_EVIDENCE_GROUPS.get(agent_name, "case_metadata")
        evidence = packet.evidence_groups.get(evidence_group, [])
        lines = [
            user_message.strip(),
            "",
            "[local-case]",
            f"case_label: {packet.case_label}",
            f"packet_hash: {packet.packet_hash}",
            f"evidence_group: {evidence_group}",
            "[/local-case]",
            "",
            f"Local case title: {packet.title}",
            "Use only the supplied evidence and cite its evidence line ids."
        ]
        if evidence:
            lines.extend(["", "Evidence lines:"])
            lines.extend(_evidence_text(item) for item in evidence)
        else:
            lines.extend(
                [
                    "",
                    "No raw log evidence is assigned to this test endpoint."
                ]
            )
        return "\n".join(lines)

    def _load_packets(self) -> dict[str, CasePacket]:
        packets = {}
        if not self.packet_directory.exists():
            return packets

        for path in sorted(self.packet_directory.glob("*.json")):
            data = json.loads(path.read_text(encoding = "utf-8"))
            _validate_packet(data, path)
            packet = CasePacket(data)
            if packet.case_label in packets:
                raise ValueError(f"Duplicate local cyber case: {packet.case_label}")
            packets[packet.case_label] = packet
        return packets


def extract_case_metadata(text: str) -> CaseMetadata | None:
    matches = list(CASE_BLOCK_PATTERN.finditer(text))
    if not matches:
        return None
    metadata = [
        CaseMetadata(
            case_label = match.group("case_label").upper(),
            packet_hash = match.group("packet_hash").lower(),
            evidence_group = match.group("evidence_group").lower()
        )
        for match in matches
    ]
    if len(set(metadata)) > 1:
        raise ValueError("A request cannot contain conflicting local-case blocks.")
    return metadata[0]


def packet_hash(packet: dict) -> str:
    hash_input = {
        key: value
        for key, value in packet.items()
        if key != "packet_hash"
    }
    encoded = json.dumps(
        hash_input,
        ensure_ascii = False,
        sort_keys = True,
        separators = (",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_packet(data: dict, path: Path) -> None:
    required = {
        "case_label",
        "title",
        "dataset",
        "time_window",
        "evidence_groups",
        "packet_hash"
    }
    missing = sorted(required - data.keys())
    if missing:
        raise ValueError(f"{path.name} is missing fields: {', '.join(missing)}")
    if not CASE_LABEL_PATTERN.fullmatch(str(data["case_label"])):
        raise ValueError(f"{path.name} has an invalid case label.")
    if not HASH_PATTERN.fullmatch(str(data["packet_hash"])):
        raise ValueError(f"{path.name} has an invalid packet hash.")
    if packet_hash(data) != data["packet_hash"]:
        raise ValueError(f"{path.name} does not match its saved packet hash.")
    if not isinstance(data["evidence_groups"], dict):
        raise ValueError(f"{path.name} evidence_groups must be an object.")
    for group_name, evidence in data["evidence_groups"].items():
        if not isinstance(evidence, list):
            raise ValueError(f"{path.name} group {group_name} must be a list.")
        for item in evidence:
            if not all(key in item for key in ("evidence_id", "timestamp", "source", "event")):
                raise ValueError(f"{path.name} contains an incomplete evidence line.")


def _evidence_text(item: dict) -> str:
    return (
        f"{item['evidence_id']} | {item['timestamp']} | "
        f"{item['source']} | {item['event']}"
    )

