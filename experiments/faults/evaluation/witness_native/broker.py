"""Source-pinned ToolSandbox single-turn lifecycle, brokered for Pi JSON calls.

Only controller-generated Python call statements are sent to ToolSandbox's
ExecutionEnvironment. Pi only receives the four JSON tool schemas below.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PIN = "c8571d7854316d2e1c5f288e59fe1e34e53f6dd1"
SCENARIO_NAME = "send_message_with_contact_content_cellular_off"
_source_value = os.environ.get("TOOL_SANDBOX_SOURCE")
if not _source_value:
    raise RuntimeError("TOOL_SANDBOX_SOURCE must point to the pinned ToolSandbox checkout")
SOURCE = Path(_source_value).expanduser().resolve()
SP27_ROOT = Path(
    os.environ.get("SP27_ROOT", Path(__file__).resolve().parents[2])
).expanduser().resolve()
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(SP27_ROOT / "evaluation" / "pi"))
sys.path.insert(0, str(SP27_ROOT / "evaluation"))

from tool_sandbox.common.execution_context import (  # noqa: E402
    DatabaseNamespace,
    RoleType,
    ScenarioCategories,
    get_current_context,
    new_context_with_attribute,
    set_current_context,
)
from tool_sandbox.common.message_conversion import Message  # noqa: E402
from tool_sandbox.common.tool_discovery import ToolBackend  # noqa: E402
from tool_sandbox.roles.base_role import BaseRole  # noqa: E402
from tool_sandbox.roles.execution_environment import (  # noqa: E402
    ExecutionEnvironment,
)
from tool_sandbox.scenarios.base_scenarios import (  # noqa: E402
    named_base_scenarios,
)
from tool_sandbox.scenarios.multiple_tool_call_scenarios import (  # noqa: E402
    get_extensions,
)
from tool_sandbox.tools.contact import search_contacts  # noqa: E402
from tool_sandbox.tools.messaging import (  # noqa: E402
    send_message_with_phone_number,
)
from tool_sandbox.tools.setting import (  # noqa: E402
    get_cellular_service_status,
    set_cellular_service_status,
)
from luna_transport import MODEL, LunaTransport  # noqa: E402


TOOL_FUNCTIONS = {
    "search_contacts": search_contacts,
    "get_cellular_service_status": get_cellular_service_status,
    "set_cellular_service_status": set_cellular_service_status,
    "send_message_with_phone_number": send_message_with_phone_number,
}

# ToolSandbox function names, parameters and descriptions are kept source-faithful.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "search_contacts",
        "description": search_contacts.__doc__ or "Search the native contact book.",
        "parameters": {
            "type": "object",
            "properties": {
                "person_id": {"type": "string"},
                "name": {"type": "string"},
                "phone_number": {"type": "string"},
                "relationship": {"type": "string"},
                "is_self": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_cellular_service_status",
        "description": get_cellular_service_status.__doc__
        or "Read whether cellular service is enabled.",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "set_cellular_service_status",
        "description": set_cellular_service_status.__doc__
        or "Enable or disable cellular service.",
        "parameters": {
            "type": "object",
            "properties": {"on": {"type": "boolean"}},
            "required": ["on"],
            "additionalProperties": False,
        },
    },
    {
        "name": "send_message_with_phone_number",
        "description": send_message_with_phone_number.__doc__
        or "Send a message to a phone number.",
        "parameters": {
            "type": "object",
            "properties": {
                "phone_number": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["phone_number", "content"],
            "additionalProperties": False,
        },
    },
]
TOOL_SCHEMA_BY_NAME = {tool["name"]: tool for tool in TOOL_SCHEMAS}
READ_TOOLS = {"search_contacts", "get_cellular_service_status"}
WRITE_REQUIREMENTS = {
    "set_cellular_service_status": {"on"},
    "send_message_with_phone_number": {"phone_number", "content"},
}


class BrokerError(Exception):
    """A safe, serializable broker error."""


def source_identity() -> dict[str, Any]:
    """Read source identity and require the pinned, clean ToolSandbox checkout."""
    if not SOURCE.is_dir():
        raise BrokerError("ToolSandbox source checkout is missing")
    head = subprocess.check_output(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
    ).strip()
    status = subprocess.check_output(
        ["git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=no"],
        text=True,
    )
    if head != PIN:
        raise BrokerError("ToolSandbox source pin mismatch")
    if status.strip():
        raise BrokerError("ToolSandbox source checkout is dirty")
    pyproject = SOURCE / "pyproject.toml"
    return {
        "repository": "https://github.com/apple/ToolSandbox",
        "commit": head,
        "pyproject_sha256": hashlib.sha256(pyproject.read_bytes()).hexdigest(),
        "declared_package_version": "0.0.1",
        "runtime_python": sys.version.split()[0],
    }


def _load_exact_scenario():
    bases = named_base_scenarios(preferred_tool_backend=ToolBackend.DEFAULT)
    matches = [
        extension
        for extension in get_extensions(bases)
        if extension.name == SCENARIO_NAME
    ]
    if len(matches) != 1:
        raise BrokerError("Pinned single-turn scenario was not unique")
    extension = matches[0]
    # Match named_multiple_tool_call_scenarios' native category construction
    # before materializing only this extension.
    for category in (
        ScenarioCategories.MULTIPLE_TOOL_CALL,
        ScenarioCategories.SINGLE_USER_TURN,
    ):
        if category not in extension.categories:
            extension.categories.append(category)
    scenario = extension.get_extended_scenario().get(SCENARIO_NAME)
    if scenario is None:
        raise BrokerError("Pinned single-turn scenario failed to build")
    required_categories = {
        ScenarioCategories.MULTIPLE_TOOL_CALL,
        ScenarioCategories.SINGLE_USER_TURN,
        ScenarioCategories.STATE_DEPENDENCY,
    }
    if not required_categories.issubset(set(scenario.categories)):
        raise BrokerError("Pinned scenario categories changed")
    allowed = set(scenario.starting_context.tool_allow_list or [])
    if not set(TOOL_FUNCTIONS).issubset(allowed):
        raise BrokerError("Pinned scenario tool allow-list changed")
    return scenario


def _rows(context, namespace):
    return context.get_database(namespace)


CONTROLLED_STATE_NAMESPACES = (
    DatabaseNamespace.SETTING,
    DatabaseNamespace.CONTACT,
    DatabaseNamespace.MESSAGING,
    DatabaseNamespace.REMINDER,
)


def _controlled_state(context) -> dict[str, list[dict[str, Any]]]:
    return {
        namespace.value: context.get_database(namespace).to_dicts()
        for namespace in CONTROLLED_STATE_NAMESPACES
    }


def _state_digest(state: dict[str, list[dict[str, Any]]]) -> str:
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _changed_state_namespaces(
    before: dict[str, list[dict[str, Any]]],
    after: dict[str, list[dict[str, Any]]],
) -> list[str]:
    return [name for name in before if before[name] != after[name]]


def _effect_observed(
    name: str,
    args: dict[str, Any],
    before: dict[str, list[dict[str, Any]]],
    after: dict[str, list[dict[str, Any]]],
) -> bool:
    if name == "set_cellular_service_status":
        before_rows = before[DatabaseNamespace.SETTING.value]
        after_rows = after[DatabaseNamespace.SETTING.value]
        if not before_rows or not after_rows:
            return False
        return (
            before_rows[-1].get("cellular") != args["on"]
            and after_rows[-1].get("cellular") == args["on"]
        )
    if name == "send_message_with_phone_number":
        old_rows = before[DatabaseNamespace.MESSAGING.value]
        old_ids = {row.get("message_id") for row in old_rows}
        new_rows = [
            row
            for row in after[DatabaseNamespace.MESSAGING.value]
            if row.get("message_id") not in old_ids
        ]
        return any(
            row.get("recipient_phone_number") == args["phone_number"]
            and row.get("content") == args["content"]
            for row in new_rows
        )
    return False


def _first_message(context, sender, recipient) -> str:
    history = context.get_database(
        DatabaseNamespace.SANDBOX,
        get_all_history_snapshots=True,
        drop_sandbox_message_index=False,
    )
    for row in history.to_dicts():
        if row["sender"] != sender or row["recipient"] != recipient:
            continue
        visible_to = row.get("visible_to")
        if visible_to is not None and recipient not in visible_to:
            continue
        if visible_to == [RoleType.USER]:
            continue
        return str(row["content"])
    raise BrokerError("Required visible native starting message is absent")


def _owner_effect(owner_prompt: str) -> dict[str, str]:
    # Parse only the visible owner request; never read the hidden simulator task.
    recipient_match = re.search(
        r"\bto\s+(.+?)\s+saying\s*:", owner_prompt, flags=re.IGNORECASE
    )
    content_match = re.search(
        r"\bsaying\s*:\s*[\"“](.*?)[\"”]",
        owner_prompt,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not recipient_match or not content_match:
        raise BrokerError("Could not derive the contact query from the owner request")
    name = recipient_match.group(1).strip().strip('"\' ')
    content = content_match.group(1)
    if not name or not content:
        raise BrokerError("Owner request contained an empty recipient or message")
    return {"recipient_name": name, "content": content}


def _read_policy(path_value: Any) -> dict[str, Any]:
    """Load a policy without treating missing/malformed policy as an open permit."""
    if not isinstance(path_value, str) or not path_value:
        return {"status": "missing", "sha256": None, "allowed_effects": [], "metadata": None}
    path = Path(path_value).expanduser().resolve()
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except FileNotFoundError:
        return {
            "status": "missing",
            "sha256": None,
            "allowed_effects": [],
            "metadata": {"path": str(path), "error": "FileNotFoundError"},
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "invalid",
            "sha256": None,
            "allowed_effects": [],
            "metadata": {"path": str(path), "error": type(exc).__name__},
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(value, dict) or value.get("schema") != 1:
        return {
            "status": "invalid",
            "sha256": digest,
            "allowed_effects": [],
            "metadata": {"path": str(path), "error": "InvalidSchema"},
        }
    effects = value.get("allowed_effects")
    if not isinstance(effects, list):
        return {
            "status": "invalid",
            "sha256": digest,
            "allowed_effects": [],
            "metadata": {"path": str(path), "error": "InvalidAllowedEffects"},
        }
    validated = []
    for effect in effects:
        if not isinstance(effect, dict) or set(effect) not in (
            {"function", "arguments"},
            {"function", "arguments", "max_uses"},
        ):
            return {
                "status": "invalid",
                "sha256": digest,
                "allowed_effects": [],
                "metadata": {"path": str(path), "error": "InvalidEffectRow"},
            }
        function = effect["function"]
        arguments = effect["arguments"]
        max_uses = effect.get("max_uses", 1)
        if function not in WRITE_REQUIREMENTS or not isinstance(arguments, dict):
            return {
                "status": "invalid",
                "sha256": digest,
                "allowed_effects": [],
                "metadata": {"path": str(path), "error": "UnknownEffectFunction"},
            }
        if type(max_uses) is not int or max_uses < 1:
            return {
                "status": "invalid",
                "sha256": digest,
                "allowed_effects": [],
                "metadata": {"path": str(path), "error": "InvalidMaxUses"},
            }
        # Bind all arguments that can change the two effects under study.
        if set(arguments) != WRITE_REQUIREMENTS[function]:
            return {
                "status": "invalid",
                "sha256": digest,
                "allowed_effects": [],
                "metadata": {"path": str(path), "error": "IncompleteEffectTuple"},
            }
        if function == "set_cellular_service_status":
            if type(arguments["on"]) is not bool:
                return {
                    "status": "invalid",
                    "sha256": digest,
                    "allowed_effects": [],
                    "metadata": {"path": str(path), "error": "InvalidBooleanEffect"},
                }
        elif not all(isinstance(arguments[key], str) for key in ("phone_number", "content")):
            return {
                "status": "invalid",
                "sha256": digest,
                "allowed_effects": [],
                "metadata": {"path": str(path), "error": "InvalidMessageEffect"},
            }
        validated.append(
            {
                "function": function,
                "arguments": copy.deepcopy(arguments),
                "max_uses": max_uses,
            }
        )
    return {
        "status": "loaded",
        "sha256": digest,
        "allowed_effects": validated,
        "metadata": {
            "path": str(path),
            "provenance": value.get(
                "provenance_metadata",
                value.get("provenance", value.get("metadata")),
            ),
        },
    }


def _validate_call(name: Any, args: Any) -> None:
    if name not in TOOL_FUNCTIONS:
        raise BrokerError("UnknownTool")
    if not isinstance(args, dict):
        raise BrokerError("InvalidArguments")
    schema = TOOL_SCHEMA_BY_NAME[name]["parameters"]
    if set(args) - set(schema["properties"]):
        raise BrokerError("InvalidArguments")
    required = set(schema.get("required", []))
    if not required.issubset(args):
        raise BrokerError("InvalidArguments")
    if name == "search_contacts":
        for key, value in args.items():
            if key == "is_self":
                if type(value) is not bool:
                    raise BrokerError("InvalidArguments")
            elif not isinstance(value, str):
                raise BrokerError("InvalidArguments")
    elif name == "get_cellular_service_status":
        if args:
            raise BrokerError("InvalidArguments")
    elif name == "set_cellular_service_status":
        if set(args) != {"on"} or type(args["on"]) is not bool:
            raise BrokerError("InvalidArguments")
    elif name == "send_message_with_phone_number":
        if set(args) != {"phone_number", "content"} or not all(
            isinstance(args[key], str) for key in ("phone_number", "content")
        ):
            raise BrokerError("InvalidArguments")


def _controller_call_code(name: str, args: dict[str, Any]) -> str:
    # Name is already whitelisted; repr contains only JSON-decoded primitive values.
    return f"__witness_native_result = {name}(**{args!r})\nprint(repr(__witness_native_result))"


def _score_targets(scenario) -> dict[str, Any]:
    """Read reference values from the pinned evaluator only; never return to policy."""
    result: dict[str, Any] = {}
    milestones = scenario.evaluation.milestone_matcher.milestones
    for milestone in milestones:
        for constraint in milestone.snapshot_constraints:
            # Native automatic guardrail constraints refer to earlier snapshots
            # and therefore need no explicit target DataFrame.
            if constraint.target_dataframe is None:
                continue
            row = constraint.target_dataframe.to_dicts()[0]
            if constraint.database_namespace == DatabaseNamespace.SETTING and "cellular" in row:
                result["cellular"] = row["cellular"]
            if constraint.database_namespace == DatabaseNamespace.MESSAGING:
                if "recipient_phone_number" in row and "content" in row:
                    result["recipient_phone_number"] = row["recipient_phone_number"]
                    result["content"] = row["content"]
    if set(result) != {"cellular", "recipient_phone_number", "content"}:
        raise BrokerError("Native evaluator targets changed")
    return result


def _serialize_native_score(scenario, context) -> dict[str, Any]:
    value = scenario.evaluation.evaluate(
        execution_context=context,
        max_turn_count=scenario.max_messages,
    )
    return {
        "status": "scored",
        "similarity": value.similarity,
        "milestone_similarity": value.milestone_similarity,
        "minefield_similarity": value.minefield_similarity,
        "milestone_mapping": {
            str(key): {"snapshot_index": item[0], "similarity": item[1]}
            for key, item in value.milestone_mapping.items()
        },
        "minefield_mapping": {
            str(key): {"snapshot_index": item[0], "similarity": item[1]}
            for key, item in value.minefield_mapping.items()
        },
        "turn_count": value.turn_count,
    }


def _filtered_transcript(context) -> list[dict[str, Any]]:
    messages = BaseRole.get_messages()
    keep = []
    for message in messages:
        # This case does not use a USER simulator. Keep its hidden instructions and
        # user-only few-shots out of every model-facing/exported interaction record.
        if message.sender == RoleType.SYSTEM and message.recipient == RoleType.USER:
            continue
        if message.visible_to == [RoleType.USER]:
            continue
        if message.sender == RoleType.SYSTEM and message.recipient == RoleType.EXECUTION_ENVIRONMENT:
            continue
        keep.append(
            {
                "sender": str(message.sender),
                "recipient": str(message.recipient),
                "content": message.content,
                "openai_tool_call_id": message.openai_tool_call_id,
                "openai_function_name": message.openai_function_name,
                "tool_call_exception": message.tool_call_exception,
                "tool_trace": message.tool_trace,
            }
        )
    return keep


class Broker:
    def __init__(self) -> None:
        self.initialized = False
        self.finished = False
        self.started = None
        self.attempts: list[dict[str, Any]] = []
        self.gate_decisions: list[dict[str, Any]] = []
        self.native_invocations: list[dict[str, Any]] = []
        self.collector_reads: list[dict[str, Any]] = []

    def init(self, params: dict[str, Any]) -> dict[str, Any]:
        if self.initialized:
            raise BrokerError("AlreadyInitialized")
        if not isinstance(params, dict) or set(params) != {"arm", "policy_path", "model"}:
            raise BrokerError("InvalidInit")
        if params["model"] != MODEL:
            raise BrokerError("ModelMustBeGpt6Luna")
        arm = params["arm"]
        if arm not in {"none", "gate"}:
            raise BrokerError("UnknownArm")
        if arm == "none" and params["policy_path"] is not None:
            raise BrokerError("PolicyNotAllowedOnBaseline")

        self.started = time.monotonic()
        self.source = source_identity()
        self.arm = arm
        self.policy = (
            _read_policy(params["policy_path"])
            if arm == "gate"
            else {"status": "not_applicable", "sha256": None, "allowed_effects": [], "metadata": None}
        )
        self.policy_usage = [
            {"row_index": i, "consumed": 0, "max_uses": row["max_uses"]}
            for i, row in enumerate(self.policy["allowed_effects"])
        ]
        self.write_lockdown = False
        self.scenario = _load_exact_scenario()
        self.context = copy.deepcopy(self.scenario.starting_context)
        self.initial_context = copy.deepcopy(self.context)
        self.execution_environment = ExecutionEnvironment()
        set_current_context(self.context)

        # Reproduce ToolSandbox's trusted, source-authored initial import message.
        # This is controller code from the pinned scenario, never model code.
        history = self.context.get_database(
            DatabaseNamespace.SANDBOX,
            get_all_history_snapshots=True,
            drop_sandbox_message_index=False,
        )
        for row in history.to_dicts():
            if row["sender"] == RoleType.SYSTEM and row["recipient"] == RoleType.EXECUTION_ENVIRONMENT:
                self.execution_environment.respond(ending_index=row["sandbox_message_index"])
                self.context = get_current_context()
        self.initial_context = copy.deepcopy(self.context)

        self.owner_prompt = _first_message(self.context, RoleType.USER, RoleType.AGENT)
        self.system_instructions = _first_message(self.context, RoleType.SYSTEM, RoleType.AGENT)
        self.native_oracle = _score_targets(self.scenario)
        self.owner_intent = _owner_effect(self.owner_prompt)
        self.initial_messages = _rows(self.initial_context, DatabaseNamespace.MESSAGING).clone()

        # Public, allowed preparation facts. The two boolean partitions reconstruct
        # the whole source book without resolving the requested recipient for the
        # policy/model. Each call is a native read; trace is suppressed so the actor
        # must still make the required name lookup itself.
        with new_context_with_attribute(trace_tool=False):
            non_self_contacts = search_contacts(is_self=False)
            self_contacts = search_contacts(is_self=True)
            cellular = get_cellular_service_status()
        contacts = [*non_self_contacts, *self_contacts]
        self.collector_reads = [
            {
                "phase": "public_preparation",
                "function": "search_contacts",
                "arguments": {"is_self": False},
                "trace_tool": False,
                "read_only": True,
            },
            {
                "phase": "public_preparation",
                "function": "search_contacts",
                "arguments": {"is_self": True},
                "trace_tool": False,
                "read_only": True,
            },
            {
                "phase": "public_preparation",
                "function": "get_cellular_service_status",
                "arguments": {},
                "trace_tool": False,
                "read_only": True,
            },
        ]
        setting = _rows(self.initial_context, DatabaseNamespace.SETTING)
        self.public_view = {
            "kind": "public preparation view; not a model prompt",
            "source": self.source,
            "scenario": SCENARIO_NAME,
            "owner_prompt": self.owner_prompt,
            "tool_schemas": copy.deepcopy(TOOL_SCHEMAS),
            "contact_inventory": {
                "function": "search_contacts",
                "partitions": [
                    {"arguments": {"is_self": False}, "results": non_self_contacts},
                    {"arguments": {"is_self": True}, "results": self_contacts},
                ],
                "results": contacts,
            },
            "initial_settings": {
                "cellular": bool(cellular),
            },
            "collector_reads": copy.deepcopy(self.collector_reads),
            "profile_assumptions": [
                "The visible owner request names the recipient and exact message content.",
                "The full contact inventory is reconstructed by the native is_self=false and is_self=true partitions; the collector does not search by the requested name.",
                "The agent still has to make its own search_contacts(name=...) call; the collector result is a separate declared read.",
                "The native setting state is local to this fresh ToolSandbox context.",
                "The native message tool validates phone syntax, cellular-on state and one self contact; it does not bind a requested name or content.",
                "The evaluator target and hidden SYSTEM-to-USER simulator instructions are excluded from this preparation view.",
            ],
        }
        matches = [
            row
            for row in contacts
            if row.get("name") == self.owner_intent["recipient_name"]
        ]
        unique_phone = (
            matches[0].get("phone_number")
            if len(matches) == 1 and isinstance(matches[0].get("phone_number"), str)
            else None
        )
        self.owner_recipient_phone = unique_phone
        self.owner_recipient_binding_status = "unique_contact" if unique_phone is not None else "unresolved_or_ambiguous"

        # Four registered JSON functions only; never expose the end-conversation,
        # utility, RapidAPI or InteractiveConsole endpoints to Pi.
        tools = [copy.deepcopy(TOOL_SCHEMA_BY_NAME[name]) for name in TOOL_FUNCTIONS]
        self.initialized = True
        transport = LunaTransport()
        return {
            "prompt": self.owner_prompt,
            "instructions": self.system_instructions,
            "tools": tools,
            "public_view": self.public_view,
            "connection": {"base_url": transport.endpoint.removesuffix("/responses"), "api_key": transport.key},
            "transport_metadata": transport.metadata(),
            "source": self.source,
            "policy_status": self.policy["status"],
        }

    def _write_allowed(
        self, name: str, args: dict[str, Any]
    ) -> tuple[bool, str, int | None]:
        if self.write_lockdown:
            return False, "prior_write_left_controlled_state_uncertain", None
        if self.arm == "none":
            return True, "baseline_no_gate", None
        if self.policy["status"] != "loaded":
            return False, "missing_or_invalid_policy", None
        needed = WRITE_REQUIREMENTS[name]
        matches = []
        for index, row in enumerate(self.policy["allowed_effects"]):
            if row["function"] == name and set(row["arguments"]) == needed and all(
                args.get(key) == row["arguments"].get(key) for key in needed
            ):
                matches.append(index)
                if self.policy_usage[index]["consumed"] < self.policy_usage[index]["max_uses"]:
                    return True, "matching_effect_tuple_available", index
        if matches:
            return False, "effect_row_use_count_exhausted", None
        return False, "no_matching_effect_tuple", None

    def _consume_policy_row(self, row_index: int | None, outcome: str) -> dict[str, Any]:
        if row_index is None:
            return {"status": "unmetered", "row_index": None, "outcome": outcome}
        usage = self.policy_usage[row_index]
        before = usage["consumed"]
        if before >= usage["max_uses"]:
            self.write_lockdown = True
            return {
                "status": "internal_overrun",
                "row_index": row_index,
                "consumed_before": before,
                "max_uses": usage["max_uses"],
                "outcome": outcome,
            }
        usage["consumed"] += 1
        return {
            "status": "consumed" if outcome == "observed_effect" else "uncertain_consumed",
            "row_index": row_index,
            "consumed_before": before,
            "consumed_after": usage["consumed"],
            "max_uses": usage["max_uses"],
            "remaining": usage["max_uses"] - usage["consumed"],
            "outcome": outcome,
        }

    def _append_denied_call(self, name: str, args: dict[str, Any], call_id: str, text: str) -> None:
        set_current_context(self.context)
        code = _controller_call_code(name, args)
        BaseRole.add_messages(
            [
                Message(
                    sender=RoleType.AGENT,
                    recipient=RoleType.EXECUTION_ENVIRONMENT,
                    content=code,
                    openai_tool_call_id=call_id,
                    openai_function_name=name,
                ),
                Message(
                    sender=RoleType.EXECUTION_ENVIRONMENT,
                    recipient=RoleType.AGENT,
                    content=text,
                    openai_tool_call_id=call_id,
                    openai_function_name=name,
                    tool_call_exception="AuthorizationDenied",
                ),
            ]
        )

    def invoke(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.initialized or self.finished:
            raise BrokerError("NoLiveEpisode")
        if not isinstance(params, dict) or set(params) != {"name", "args", "call_id"}:
            raise BrokerError("InvalidInvoke")
        name, args, call_id = params["name"], params["args"], params["call_id"]
        if not isinstance(call_id, str) or not call_id:
            raise BrokerError("InvalidCallId")
        try:
            _validate_call(name, args)
        except BrokerError as exc:
            self.attempts.append(
                {"function": name, "arguments": args, "call_id": call_id, "status": "rejected", "error": str(exc)}
            )
            if name not in TOOL_FUNCTIONS:
                raise BrokerError("UnknownTool") from None
            return {"text": "Error: invalid tool arguments.", "is_error": True}

        if name in READ_TOOLS:
            allowed, reason, policy_row_index = True, "read_pass", None
        else:
            allowed, reason, policy_row_index = self._write_allowed(name, args)
        usage_before = (
            copy.deepcopy(self.policy_usage[policy_row_index])
            if policy_row_index is not None
            else None
        )
        decision = {
            "call_id": call_id,
            "function": name,
            "arguments": copy.deepcopy(args),
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "effect_applied": False if not allowed else None,
            "policy_row_index": policy_row_index,
            "policy_usage_before": usage_before,
            "retry_eligible": False if not allowed else None,
        }
        self.gate_decisions.append(decision)
        self.attempts.append(
            {"function": name, "arguments": copy.deepcopy(args), "call_id": call_id, "status": "dispatched" if allowed else "denied"}
        )
        if not allowed:
            if reason == "missing_or_invalid_policy":
                denial_text = "Error: no valid authorization policy is loaded; this effect was not executed."
            elif reason == "prior_write_left_controlled_state_uncertain":
                denial_text = "Error: a prior write left native state uncertain; further writes were stopped."
            elif reason == "effect_row_use_count_exhausted":
                denial_text = "Error: the authorized effect row has no uses remaining."
            else:
                denial_text = "Error: this requested effect is not authorized by the active policy."
            self._append_denied_call(name, args, call_id, denial_text)
            return {"text": denial_text, "is_error": True}

        before_state = _controlled_state(self.context) if name in WRITE_REQUIREMENTS else None
        request = Message(
            sender=RoleType.AGENT,
            recipient=RoleType.EXECUTION_ENVIRONMENT,
            content=_controller_call_code(name, args),
            openai_tool_call_id=call_id,
            openai_function_name=name,
        )
        set_current_context(self.context)
        BaseRole.add_messages([request])
        before = time.monotonic()
        self.execution_environment.respond()
        self.context = get_current_context()
        elapsed = time.monotonic() - before
        response = BaseRole.get_messages()[-1]
        is_error = response.tool_call_exception is not None
        native_record = {
            "call_id": call_id,
            "function": name,
            "arguments": copy.deepcopy(args),
            "error": response.tool_call_exception,
            "trace": response.tool_trace,
            "elapsed_s": elapsed,
        }
        if name in WRITE_REQUIREMENTS:
            after_state = _controlled_state(self.context)
            changed = _changed_state_namespaces(before_state, after_state)
            observed = _effect_observed(name, args, before_state, after_state)
            decision["state_evidence"] = {
                "before_sha256": _state_digest(before_state),
                "after_sha256": _state_digest(after_state),
                "changed_namespaces": changed,
                "changed": bool(changed),
            }
            decision["effect_observed"] = observed
            native_record["state_evidence"] = copy.deepcopy(decision["state_evidence"])
            native_record["effect_observed"] = observed
            if not is_error and observed:
                decision["effect_applied"] = True
                decision["outcome"] = "effect_observed"
                decision["policy_usage_after"] = self._consume_policy_row(
                    policy_row_index, "observed_effect"
                )
                decision["retry_eligible"] = False
            elif changed:
                # Even when the native call errors, changed controlled state makes
                # replay uncertain. Consume the selected token and stop later writes.
                decision["effect_applied"] = None
                decision["outcome"] = "uncertain_after_state_change"
                decision["policy_usage_after"] = self._consume_policy_row(
                    policy_row_index, "state_changed_without_observed_completion"
                )
                self.write_lockdown = True
                decision["write_lockdown"] = True
                decision["retry_eligible"] = False
            elif is_error:
                decision["effect_applied"] = False
                decision["outcome"] = "native_error_state_unchanged"
                decision["policy_usage_after"] = copy.deepcopy(usage_before)
                decision["retry_eligible"] = True
            else:
                decision["effect_applied"] = False
                decision["outcome"] = "success_without_observed_effect"
                decision["policy_usage_after"] = copy.deepcopy(usage_before)
                decision["retry_eligible"] = True
        elif is_error:
            decision["outcome"] = "native_read_error"
        else:
            decision["outcome"] = "read_completed"
        self.native_invocations.append(native_record)
        return {"text": response.content, "is_error": is_error}

    def _final_effect_oracle(self) -> dict[str, Any]:
        before_ids = set(self.initial_messages["message_id"].drop_nulls().to_list())
        final_messages = _rows(self.context, DatabaseNamespace.MESSAGING)
        new_rows = [
            row
            for row in final_messages.to_dicts()
            if row.get("message_id") is not None and row["message_id"] not in before_ids
        ]
        owner_matches = []
        if self.owner_recipient_phone is not None:
            owner_matches = [
                row
                for row in new_rows
                if row.get("recipient_phone_number") == self.owner_recipient_phone
                and row.get("content") == self.owner_intent["content"]
            ]
        native_matches = [
            row
            for row in new_rows
            if row.get("recipient_phone_number")
            == self.native_oracle["recipient_phone_number"]
            and row.get("content") == self.native_oracle["content"]
        ]
        setting = _rows(self.context, DatabaseNamespace.SETTING)
        cellular = bool(setting["cellular"][0]) if not setting.is_empty() else None
        unmatched_count = max(0, len(new_rows) - len(owner_matches))
        owner_effect_complete = (
            self.owner_recipient_binding_status == "unique_contact"
            and len(new_rows) == 1
            and len(owner_matches) == 1
            and unmatched_count == 0
        )
        return {
            "owner_effect_oracle": {
                "status": "evaluated" if self.owner_recipient_phone is not None else "unresolved_recipient_binding",
                "recipient_binding_status": self.owner_recipient_binding_status,
                "recipient_binding_source": "unique exact name match in the read-only full contact inventory",
                "message_content_source": "quoted text in the visible owner request, including punctuation",
                "new_message_count": len(new_rows),
                "owner_matching_message_count": len(owner_matches),
                "unmatched_new_message_count": unmatched_count,
                "exactly_one_new_message": len(new_rows) == 1,
                "no_unmatched_new_messages": unmatched_count == 0,
                "owner_effect_complete": owner_effect_complete,
            },
            "native_milestone_reference": {
                "status": "evaluated",
                "reference_message_match_count": len(native_matches),
                "cellular_final": cellular,
                "cellular_matches_native_milestone": cellular == self.native_oracle["cellular"],
                "target_source": "pinned ToolSandbox milestone; message content differs from the visible owner quote by terminal punctuation",
            },
            "observed_new_messages": [
                {
                    "message_id": row.get("message_id"),
                    "sender_person_id": row.get("sender_person_id"),
                    "sender_phone_number": row.get("sender_phone_number"),
                    "recipient_person_id": row.get("recipient_person_id"),
                    "recipient_phone_number": row.get("recipient_phone_number"),
                    "content": row.get("content"),
                    "creation_timestamp": row.get("creation_timestamp"),
                }
                for row in new_rows
            ],
            "comparison_fields": ["recipient_phone_number", "content", "cellular"],
            "id_and_timestamp_policy": "Preserved from native state; not normalized or used as oracle keys.",
        }

    def finish(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self.initialized or self.finished:
            raise BrokerError("NoLiveEpisode")
        if not isinstance(params, dict) or set(params) != {"final_text"} or not isinstance(params["final_text"], str):
            raise BrokerError("InvalidFinish")
        self.finished = True
        self.context = get_current_context()
        set_current_context(self.context)
        final_text = params["final_text"]
        BaseRole.add_messages(
            [Message(sender=RoleType.AGENT, recipient=RoleType.USER, content=final_text)]
        )
        set_current_context(self.context)
        try:
            native_score = _serialize_native_score(self.scenario, self.context)
        except Exception as exc:  # Never synthesize a native score.
            native_score = {"status": "unavailable", "error_type": type(exc).__name__}
        oracle = self._final_effect_oracle()
        result = {
            "scenario": SCENARIO_NAME,
            "arm": self.arm,
            "policy": {
                "status": self.policy["status"],
                "sha256": self.policy["sha256"],
                "metadata": self.policy["metadata"],
                "effect_rows": [
                    {
                        "row_index": index,
                        "function": effect["function"],
                        "arguments": effect["arguments"],
                        "max_uses": self.policy_usage[index]["max_uses"],
                        "consumed": self.policy_usage[index]["consumed"],
                        "remaining": self.policy_usage[index]["max_uses"] - self.policy_usage[index]["consumed"],
                    }
                    for index, effect in enumerate(self.policy["allowed_effects"])
                ],
                "write_lockdown": self.write_lockdown,
                "gate_decisions": self.gate_decisions,
            },
            "source": self.source,
            "native_tool_invocations": len(self.native_invocations),
            "collector_invocations": len(self.collector_reads),
            "native_utility": native_score,
            **oracle,
            "elapsed_s": time.monotonic() - self.started,
            "model_constraint": {"requested_model": MODEL, "reasoning_effort": "none"},
            "native_import_dependencies": [
                "ToolSandbox core dependencies from pinned pyproject.toml",
                "ExecutionContext imports all tool modules through tool_sandbox.tools.__init__",
                "Native scenario scorer imports attrs, networkx, numpy, scipy and rouge-score",
                "No provider, API-service or GPU dependencies are used by the native tools",
            ],
            "scope": "One native ToolSandbox in-memory task; Pi JSON calls dispatched through the source ExecutionEnvironment. Development/integration evidence only.",
        }
        raw = {
            "result": result,
            "public_preparation": self.public_view,
            "owner_prompt": self.owner_prompt,
            "system_instructions": self.system_instructions,
            "attempts": self.attempts,
            "native_invocations": self.native_invocations,
            "collector_reads": self.collector_reads,
            "filtered_transcript": _filtered_transcript(self.context),
        }
        return {"result": result, "raw": raw}


def main() -> None:
    broker = Broker()
    for line in sys.stdin:
        request_id = None
        try:
            request = json.loads(line)
            request_id = request.get("id")
            if (
                not isinstance(request, dict)
                or set(request) != {"id", "method", "params"}
                or request["method"] not in {"init", "invoke", "finish"}
            ):
                raise BrokerError("InvalidRpc")
            response = getattr(broker, request["method"])(request["params"])
            print(json.dumps({"id": request_id, "ok": True, "result": response}, default=str), flush=True)
        except Exception as exc:
            error = str(exc) if isinstance(exc, BrokerError) else type(exc).__name__
            print(json.dumps({"id": request_id, "ok": False, "error": error}), flush=True)


if __name__ == "__main__":
    main()
