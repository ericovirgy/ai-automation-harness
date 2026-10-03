"""Evidence records: one structured, redacted record per request, referenced from the audit log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_automation_harness.errors import InvariantError
from ai_automation_harness.models import canonical_json, sha256_hex


def evidence_digest(record: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(record))


class EvidenceStore:
    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}

    def put(self, ref: str, record: dict[str, Any], *, overwrite: bool = False) -> str:
        """Store a JSON-safe record and return its digest. Never replaces one silently."""
        if ref in self._records and not overwrite:
            raise InvariantError("evidence reference already exists")
        self._records[ref] = json.loads(canonical_json(record))
        return evidence_digest(self._records[ref])

    def get(self, ref: str) -> dict[str, Any] | None:
        record = self._records.get(ref)
        return json.loads(canonical_json(record)) if record is not None else None

    def refs(self) -> list[str]:
        return sorted(self._records)

    def export(self, directory: str | Path) -> list[Path]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for ref in self.refs():
            path = out / f"{ref}.json"
            path.write_text(json.dumps(self._records[ref], indent=2, sort_keys=True) + "\n")
            written.append(path)
        return written
