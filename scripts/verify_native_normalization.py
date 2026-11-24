#!/usr/bin/env python3
"""Optional verification using an installed copy of the pinned AgentDojo source."""

import json
from pathlib import Path
from agentdojo.task_suite import get_suite

root = Path(__file__).resolve().parents[1]
rows = json.loads((root / "research/data/native-parameter-normalization.json").read_text())[
    "normalizations"
]
functions = {f.name: f for f in get_suite("v1.2.2", "banking").tools}
for row in rows:
    call = row["input"]
    try:
        value = {
            "function": call["function"],
            "args": functions[call["function"]]
            .parameters.model_validate(call["args"])
            .model_dump(),
        }
    except Exception as exc:
        assert not row["valid"] and type(exc).__name__ == row["error_type"]
    else:
        assert row["valid"] and value == row["normalized"]
print(
    "Verified", len(rows), "retained native argument normalizations; no model or tool executions."
)
