"""Replay recorded effects through the pinned benchmark, with networking disabled."""

import collections
import copy
import datetime
import json
import lzma
import socket
import os
import contextlib
import io
import re
from pathlib import Path

from .paths import DATA, ROOT


def block_network(*args, **kwargs):
    raise RuntimeError("Native replay prohibits network access")


def semantic(value, key=None):
    if isinstance(value, dict):
        return {k: semantic(v, k) for k, v in value.items()}
    # The calendar implementation creates participants through a Python set and
    # reuses that list for notification recipients. Ordering of these address
    # lists is not an effect; multiplicity is retained by sorting, not deduping.
    if isinstance(value, list):
        return (
            sorted(value) if key in {"participants", "recipients"} else [semantic(v) for v in value]
        )
    return value


def install_clock(anchor):
    from agentdojo.default_suites.v1.tools import email_client, cloud_drive_client

    base = datetime.datetime.fromisoformat(anchor)
    ticks = 0

    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            nonlocal ticks
            value = base + datetime.timedelta(microseconds=ticks)
            ticks += 1
            return (
                value if tz is None else value.replace(tzinfo=datetime.timezone.utc).astimezone(tz)
            )

    class Module:
        datetime = Clock

        def __getattr__(self, name):
            return getattr(datetime, name)

    for module in [email_client, cloud_drive_client]:
        module.datetime = Module()


class Replay:
    def __init__(self):
        from agentdojo.task_suite import get_suite
        from agentdojo.functions_runtime import FunctionsRuntime, make_function
        from agentdojo.default_suites.v1.tools.calendar_client import get_current_day

        self.suites = {
            s: get_suite("v1.2.2", s) for s in ["banking", "workspace", "travel", "slack"]
        }
        self.runtimes = {}
        for name, suite in self.suites.items():
            tools = list(suite.tools)
            if "get_current_day" not in {f.name for f in tools}:
                tools.append(make_function(get_current_day))
            self.runtimes[name] = FunctionsRuntime(tools)
        socket.create_connection = block_network
        socket.socket.connect = block_network

    def episode(self, raw, suite_name=None):
        result = raw.get("result") or {}
        events = raw.get("events")
        if not isinstance(events, list) or "initial" not in raw:
            return {"status": "no_episode_trace"}
        case = result.get("case_id", "")
        suite_name = suite_name or result.get("suite") or case.split("__")[0]
        if suite_name not in self.suites:
            raise ValueError("Unknown suite: " + suite_name)
        suite = self.suites[suite_name]
        runtime = self.runtimes[suite_name]
        initial = copy.deepcopy(raw["initial"])
        state = suite.environment_type.model_validate(initial)
        if semantic(state.model_dump(mode="json")) != semantic(initial):
            raise ValueError("Initial native state did not restore exactly")
        install_clock((result.get("clock_profile") or {}).get("anchor", "2026-11-05T00:00:00"))
        executed = refused = 0
        for index, event in enumerate(events):
            before = state.model_dump(mode="json")
            if semantic(before) != semantic(event["before"]):
                raise ValueError(f"Event {index}: before-state mismatch")
            error = event.get("error")
            same = semantic(event["before"]) == semantic(event["after"])
            policy_error = event.get("controller_denied") is True or (
                isinstance(error, str)
                and any(
                    x in error
                    for x in [
                        "not allowed",
                        "not authorized",
                        "Authorization denied",
                        "not permitted",
                        "owner's confirmation",
                        "Policy gate ",
                        "policy denied",
                        "Policy denied",
                        "Shared native invocation budget exhausted",
                        "Please try other tools or arguments and continue to finish the user task:",
                    ]
                )
            )
            if policy_error:
                if not same:
                    raise ValueError(f"Event {index}: refusal changed state")
                refused += 1
                continue
            operation = event["operation"]
            _, actual_error = runtime.run_function(
                state, operation["function"], copy.deepcopy(operation["args"])
            )
            if semantic(state.model_dump(mode="json")) != semantic(event["after"]):
                raise ValueError(
                    f"Event {index} ({operation['function']}): native after-state mismatch"
                )
            if (actual_error is None) != (error is None):
                raise ValueError(f"Event {index}: native error status mismatch")
            executed += 1
        if semantic(state.model_dump(mode="json")) != semantic(raw["final"]):
            raise ValueError("Final native state mismatch")
        scores = self.score(raw, suite_name, state)
        return {
            "status": "passed",
            "executed_events": executed,
            "refused_events": refused,
            "scores_checked": scores,
        }

    def score(self, raw, suite_name, final):
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import text_content_block_from_string

        result = raw.get("result") or {}
        suite = self.suites[suite_name]
        initial = suite.environment_type.model_validate(
            raw.get("scoring_initial", raw.get("retained_original_initial", raw["initial"]))
        )
        proposals = [FunctionCall.model_validate(c) for c in raw.get("proposed_calls", [])]
        outputs = [text_content_block_from_string(raw.get("final_response", ""))]
        task_id = result.get("task_id")
        case = result.get("case_id", "")
        if not task_id:
            match = re.search(r"(user_task_\d+|injection_task_\d+)", case)
            task_id = match[0] if match else None
        count = 0
        if type(result.get("native_utility")) is bool and task_id:
            if result.get("condition") == "goal_control" or task_id.startswith("injection_task_"):
                task = suite.get_injection_task_by_id(task_id)
                value = suite._check_injection_task_security(
                    task,
                    outputs,
                    initial.model_copy(deep=True),
                    final.model_copy(deep=True),
                    proposals,
                )
            else:
                task = suite.get_user_task_by_id(task_id)
                value = suite._check_task_result(
                    task,
                    outputs,
                    initial.model_copy(deep=True),
                    final.model_copy(deep=True),
                    proposals,
                )
            if bool(value) != result["native_utility"]:
                raise ValueError("Native utility scorer mismatch")
            count += 1
        target = result.get("native_targeted_asr")
        if type(target) is bool:
            injection = result.get("injection_id")
            if not injection:
                match = re.search(r"injection_task_\d+", case)
                injection = match[0] if match else None
            if injection:
                task = suite.get_injection_task_by_id(injection)
                value = suite._check_injection_task_security(
                    task,
                    outputs,
                    initial.model_copy(deep=True),
                    final.model_copy(deep=True),
                    proposals,
                )
                if bool(value) != target:
                    raise ValueError("Native attacker-goal scorer mismatch")
                count += 1
        return count


def replay_archive(archive, out, limit=None, only=None):
    runner = Replay()
    counts = collections.Counter()
    failures = []
    with lzma.open(DATA / archive, "rt") as stream:
        for line in stream:
            record = json.loads(line)
            if archive == "fault-injection.jsonl.xz":
                if record["kind"] != "run":
                    continue
                raw = record["raw"]
                identity = record["condition"]["condition_id"]
                suite = record["condition"]["unit_id"].split("__")[0]
            elif archive == "matched-inputs.jsonl.xz":
                if record["kind"] != "run":
                    continue
                raw = record["raw"]
                identity = record["unit_id"] + "/" + record["arm"]
                suite = "banking"
            elif record["kind"] == "episode":
                raw = record["data"]
                identity = record["run"] + "/" + record["path"]
                suite = None
            else:
                continue
            if only is not None and identity not in only:
                continue
            try:
                result = runner.episode(raw, suite)
                counts[result["status"]] += 1
                counts["executed_events"] += result.get("executed_events", 0)
                counts["refused_events"] += result.get("refused_events", 0)
                counts["native_scores_checked"] += result.get("scores_checked", 0)
            except Exception as exc:
                counts["failed"] += 1
                failures.append({"record": identity, "error": str(exc)})
            counts["episodes"] += 1
            if counts["episodes"] % 250 == 0:
                print(
                    archive,
                    counts["episodes"],
                    "episodes;",
                    counts["failed"],
                    "failures",
                    flush=True,
                )
            if limit and counts["episodes"] >= limit:
                break
    report = {
        "archive": archive,
        "counts": dict(counts),
        "failures": failures,
        "model_calls": 0,
        "network_calls": 0,
        "scope": "Native state transitions for recorded calls; refused effects must leave state unchanged. This does not resample policies or actors.",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    return report


def replay_models(out):
    """Replay unique actor trajectories and both native updater permission probes."""
    runner = Replay()
    packets = {}
    references = collections.defaultdict(list)
    counts = collections.Counter()
    failures = []
    from agentdojo.functions_runtime import FunctionsRuntime

    os.environ.update(
        ENABLE_SECAGENT="True",
        SECAGENT_GENERATE="False",
        SECAGENT_UPDATE="False",
        SECAGENT_POLICY_MODEL="gpt-6-luna",
    )
    with contextlib.redirect_stderr(io.StringIO()):
        from secagent import tool as gate
    gate.api_request = block_network
    gate.available_tools = []
    suite = runner.suites["banking"]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tools = [
            f.model_copy(update={"run": gate.apply_secure_tool_wrapper(f.run)}) for f in suite.tools
        ]
    guarded = FunctionsRuntime(tools)
    original_check = gate.check_tool_call
    with lzma.open(DATA / "model-continuations.jsonl.xz", "rt") as stream:
        for line in stream:
            record = json.loads(line)
            kind = record["kind"]
            if kind == "row":
                row = record["row"]
                if row.get("raw_record_id"):
                    references[row["raw_record_id"]].append(row)
            elif kind == "packet":
                packets[record["record_id"]] = record["packet"]
            elif kind == "raw":
                raw = record["raw"]
                refs = references[record["record_id"]]
                row = next((r for r in refs if r["source"].get("kind") != "unforced"), None)
                if row is None:
                    counts["unforced_first_responses"] += 1
                    continue
                packet = packets.get(row.get("packet_record_id"))
                source = row["source"]
                try:
                    if source.get("kind") == "update":
                        assert packet is not None
                        for name, policy in [
                            ("before", packet["policy"]),
                            ("after", raw["policy_after"]),
                        ]:
                            expected = raw.get(name, {}).get("allowed")
                            if expected is None:
                                counts["unknown_permission_probes"] += 1
                                continue
                            gate.security_policy = copy.deepcopy(policy)
                            gate.init_user_query = packet["owner_request"]
                            decisions = []

                            def checked(tool_name, args):
                                try:
                                    value = original_check(tool_name, args)
                                except Exception:
                                    decisions.append(False)
                                    raise
                                decisions.append(True)
                                return value

                            gate.check_tool_call = checked
                            state = suite.environment_type.model_validate(packet["state"])
                            call = packet["original_proposal"]
                            with (
                                contextlib.redirect_stdout(io.StringIO()),
                                contextlib.redirect_stderr(io.StringIO()),
                            ):
                                guarded.run_function(
                                    state, call["function"], copy.deepcopy(call["args"])
                                )
                            gate.check_tool_call = original_check
                            if decisions != [expected]:
                                raise ValueError("Installed-policy probe mismatch: " + name)
                            counts["permission_probes"] += 1
                        counts["updater_records"] += 1
                    elif isinstance(raw.get("native"), dict):
                        native = raw["native"]
                        events = native.get("events", [])
                        final_text = raw.get("final_text")
                        if final_text is None:
                            messages = raw.get("final_context", {}).get("messages", [])
                            last = next(
                                (m for m in reversed(messages) if m.get("role") == "assistant"), {}
                            )
                            final_text = "\n".join(
                                c.get("text", "")
                                for c in last.get("content", [])
                                if isinstance(c, dict) and c.get("type") == "text"
                            )
                        metadata = {
                            "suite": raw.get("suite") or native.get("suite") or "banking",
                            "task_id": raw.get("task_id"),
                            "native_utility": native.get("native_utility"),
                            "native_targeted_asr": native.get("native_goal"),
                            "injection_id": packet.get("injection_id") if packet else None,
                        }
                        trace = {
                            "initial": events[0]["before"]
                            if events
                            else packet["native_boundary_state"],
                            "scoring_initial": packet["native_initial_state"],
                            "final": native["final"],
                            "events": events,
                            "proposed_calls": native.get("proposals", []),
                            "final_response": final_text,
                            "result": metadata,
                        }
                        if not events:
                            if semantic(trace["initial"]) != semantic(native["final"]):
                                raise ValueError("State changed without a native event")
                            state = runner.suites[
                                metadata["suite"]
                            ].environment_type.model_validate(native["final"])
                            if semantic(state.model_dump(mode="json")) != semantic(native["final"]):
                                raise ValueError("No-event state requires source-prefix replay")
                            counts["native_scores_checked"] += runner.score(
                                trace, metadata["suite"], state
                            )
                            counts["no_native_events"] += 1
                            continue
                        result = runner.episode(trace)
                        counts["native_scores_checked"] += result["scores_checked"]
                        counts["actor_trajectories"] += 1
                        counts["executed_events"] += result["executed_events"]
                        counts["refused_events"] += result["refused_events"]
                    else:
                        counts["unavailable_native_trace"] += 1
                except Exception as exc:
                    gate.check_tool_call = original_check
                    failures.append(
                        {
                            "record_id": record["record_id"],
                            "source_id": source["id"],
                            "error": str(exc),
                        }
                    )
                counts["records"] += 1
                if counts["records"] % 500 == 0:
                    print(
                        "model replay",
                        counts["records"],
                        "records;",
                        len(failures),
                        "failures",
                        flush=True,
                    )
    report = {"counts": dict(counts), "failures": failures, "model_calls": 0, "network_calls": 0}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    return report
