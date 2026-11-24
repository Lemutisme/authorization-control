"""Model-free scripted Pi-tool-call lifecycle for parent qualification.

This script is intended for later registration. It was not run during adapter
work. The script calls only the broker's four whitelisted native JSON tools.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import socket
from pathlib import Path
from typing import Any

# Broker.init constructs the shared Pi transport descriptor, but this scripted
# qualification path never sends a request. Force a non-routable local endpoint
# and remove provider keys so there is no accidental model/network path.
os.environ["PGA_API_BASE_URL"] = "http://127.0.0.1/v1"
os.environ["PGA_MODEL"] = "gpt-6-luna"
os.environ.pop("PGA_API_KEY", None)
os.environ.pop("PGA_CODEX_CONFIG", None)
def _no_network(*args, **kwargs):
    raise RuntimeError("Network forbidden during model-free native qualification")
socket.create_connection = _no_network
socket.socket.connect = _no_network
sys.path.insert(0, str(Path(__file__).resolve().parent))

from broker import Broker, _owner_effect  # noqa: E402


def _call(broker: Broker, name: str, args: dict[str, Any], call_id: str) -> dict[str, Any]:
    return broker.invoke({"name": name, "args": args, "call_id": call_id})


def run(arm: str, policy: str | None, out: Path) -> dict[str, Any]:
    broker = Broker()
    init_result = broker.init(
        {
            "arm": arm,
            "policy_path": str(Path(policy).resolve()) if policy else None,
            "model": "gpt-6-luna",
        }
    )
    owner = _owner_effect(init_result["prompt"])
    transcript: list[dict[str, Any]] = []

    lookup = _call(
        broker,
        "search_contacts",
        {"name": owner["recipient_name"]},
        "script-search-1",
    )
    transcript.append({"function": "search_contacts", **lookup})
    if lookup["is_error"]:
        final_text = "I could not resolve the requested contact, so I did not send a message."
        finished = broker.finish({"final_text": final_text})
        result = {
            **finished["result"],
            "execution": "model_free_scripted_qualification",
            "model_calls": 0,
            "scripted_calls": transcript,
        }
        return _write_report(out, result, finished["raw"], init_result["public_view"])

    try:
        contacts = ast.literal_eval(lookup["text"])
    except (ValueError, SyntaxError):
        contacts = []
    matches = [
        row
        for row in contacts
        if isinstance(row, dict) and row.get("name") == owner["recipient_name"]
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("phone_number"), str):
        final_text = "I could not uniquely resolve the requested contact, so I did not send a message."
        finished = broker.finish({"final_text": final_text})
        result = {
            **finished["result"],
            "execution": "model_free_scripted_qualification",
            "model_calls": 0,
            "scripted_calls": transcript,
        }
        return _write_report(out, result, finished["raw"], init_result["public_view"])

    status = _call(broker, "get_cellular_service_status", {}, "script-cellular-read-1")
    transcript.append({"function": "get_cellular_service_status", **status})
    if status["is_error"]:
        final_text = "I could not verify cellular service, so I did not send a message."
        finished = broker.finish({"final_text": final_text})
        result = {
            **finished["result"],
            "execution": "model_free_scripted_qualification",
            "model_calls": 0,
            "scripted_calls": transcript,
        }
        return _write_report(out, result, finished["raw"], init_result["public_view"])
    try:
        cellular_on = ast.literal_eval(status["text"])
    except (ValueError, SyntaxError):
        cellular_on = None
    if cellular_on is False:
        changed = _call(
            broker,
            "set_cellular_service_status",
            {"on": True},
            "script-cellular-write-1",
        )
        transcript.append({"function": "set_cellular_service_status", **changed})

    sent = _call(
        broker,
        "send_message_with_phone_number",
        {
            "phone_number": matches[0]["phone_number"],
            "content": owner["content"],
        },
        "script-send-1",
    )
    transcript.append({"function": "send_message_with_phone_number", **sent})
    if sent["is_error"]:
        final_text = f"I could not send the requested message to {owner['recipient_name']}."
    else:
        final_text = (
            f"Your message to {owner['recipient_name']} has been sent saying: "
            f"{owner['content']}"
        )
    finished = broker.finish({"final_text": final_text})
    result = {
        **finished["result"],
        "execution": "model_free_scripted_qualification",
        "model_calls": 0,
        "scripted_calls": transcript,
    }
    return _write_report(out, result, finished["raw"], init_result["public_view"])


def _write_report(out: Path, result: dict[str, Any], raw: dict[str, Any], public: dict[str, Any]) -> dict[str, Any]:
    report = {"result": result, "public_preparation": public, "raw": raw}
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", choices=("none", "gate"), required=True)
    parser.add_argument("--policy")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.arm == "none" and args.policy:
        parser.error("--policy is only valid with --arm gate")
    result = run(args.arm, args.policy, args.out)
    print(
        json.dumps(
            {
                "scenario": result["scenario"],
                "arm": result["arm"],
                "execution": result["execution"],
                "model_calls": result["model_calls"],
                "native_scorer": result["native_utility"]["status"],
                "owner_effect_complete": result["owner_effect_oracle"]["owner_effect_complete"],
                "output": str(args.out.resolve()),
            }
        )
    )


if __name__ == "__main__":
    main()
