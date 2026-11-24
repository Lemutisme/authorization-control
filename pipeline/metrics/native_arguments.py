"""Native banking argument normalization, with an offline recorded-input fixture."""

import copy
import json
from functools import lru_cache
from ..paths import DATA


@lru_cache(maxsize=1)
def fixtures():
    source = DATA / "native-parameter-normalization.json"
    rows = json.loads(source.read_text())["normalizations"]
    return {json.dumps(r["input"], sort_keys=True, separators=(",", ":")): r for r in rows}


def normalize_call(operation):
    call = {
        "function": operation.get("function", operation.get("name")),
        "args": operation.get("args", operation.get("arguments")),
    }
    try:
        from agentdojo.task_suite import get_suite
    except ImportError:
        key = json.dumps(call, sort_keys=True, separators=(",", ":"))
        row = fixtures().get(key)
        if row is None:
            raise ValueError("Install native dependencies to normalize a new operation")
        if not row["valid"]:
            raise ValueError("Native parameter validation rejected this operation")
        return copy.deepcopy(row["normalized"])
    function = next(f for f in get_suite("v1.2.2", "banking").tools if f.name == call["function"])
    return {
        "function": call["function"],
        "args": function.parameters.model_validate(call["args"]).model_dump(),
    }
