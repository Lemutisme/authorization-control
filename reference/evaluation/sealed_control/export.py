"""Verify/materialize explicitly selected completed X6 evidence; no model/Git calls.

Inspect is read-only. Build needs explicit --runs, matching --source NAME=DIR
trees and --protocol NAME=FILE registrations. It never discovers jobs itself.
Large text/journals are gzip packed; unchanged raw gzip bytes stay exact.
Credentials stop export. Host replacements require explicit prefixes/endpoints
and a private map outside the repository. Scores and synthetic identities stay.
"""

from __future__ import annotations
import argparse
import base64
from collections import Counter
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import parse_qs, urlsplit

VERSION = "sealed-x6-evidence-v1"
REPO = Path(__file__).resolve().parents[2]
SKIP_DIRS = {"inputs", "node_modules", "__pycache__", ".git", ".venv", "venv"}
SOURCE_SUFFIXES = {".py", ".mjs", ".js", ".json", ".jsonl", ".gz", ".md", ".txt",
                   ".toml", ".yaml", ".yml", ".lock", ".sh", ".csv", ".tex"}
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    # Hyphen belongs to the opaque/token alphabet. A word boundary alone
    # incorrectly starts a credential match after a hyphen inside provider IDs.
    # Credential fields and HTTP authorization are checked independently below.
    "credential_token": re.compile(r"(?<![A-Za-z0-9_-])(?:gh[pousr]_|github_pat_|hf_|sk-)[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    "bearer_token": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]{24,}"),
    "http_authorization": re.compile(r"(?im)\b(?:Proxy-)?Authorization\s*:\s*(?:Bearer|Basic|Token|ApiKey|Negotiate)\s+[A-Za-z0-9._~+/=-]{4,}"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}
SECRET_KEYS = {"api_key", "apikey", "access_token", "refresh_token", "client_secret",
               "authorization", "aws_secret_access_key", "private_key", "openai_api_key",
               "anthropic_api_key", "github_token"}
SAFE_PLACEHOLDERS = {"", "unused", "anonymous", "unused-anonymous-endpoint-key", "redacted"}
INTEGRITY_FIELDS = {"context_json", "request_json", "wire_request_json", "actor_context_json",
                    "source_proposal_message", "context_utf8_json"}
HOST_PATH = re.compile(r'''(?<![\w])/(?:data|root|home|tmp|mnt|var/tmp)/[^\s"'\x60()<>{}\[\],;\\]+''')
URL = re.compile(r'''https?://[^\s"'\x60<>\\]+''', re.I)
AUTHORIZATION_FIELDS = {"authorization", "proxy-authorization", "proxy_authorization"}
AUTHORIZATION_SCHEME = re.compile(r"(?i)^\s*(?:Bearer|Basic|Token|ApiKey|Api-Key|Digest|Negotiate|AWS4-HMAC-SHA256)\s+\S")


class ExportError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def decoded(data, name):
    return gzip.decompress(data) if name.endswith(".gz") else data


def safe_relative(name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not name or "\\" in name:
        raise ExportError("Unsafe relative artifact path")
    return path


def named(values):
    result = {}
    for value in values:
        if "=" not in value:
            raise ExportError("Named inputs use NAME=PATH")
        name, path = value.split("=", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in result:
            raise ExportError("Invalid or duplicate input name")
        result[name] = Path(path).resolve()
    return result


def public_endpoint(value):
    try:
        parsed = urlsplit(value.rstrip(".,);"))
        if parsed.username or parsed.password:
            raise ExportError("Credential-bearing URL discovered")
        for key, values in parse_qs(parsed.query).items():
            if key.lower() in SECRET_KEYS and any(item.lower() not in SAFE_PLACEHOLDERS for item in values):
                raise ExportError("Credential-bearing URL query discovered")
        host = parsed.hostname or ""
        if host == "localhost" or host.endswith((".internal", ".local")):
            return False
        try:
            return not ipaddress.ip_address(host).is_private
        except ValueError:
            return True
    except ValueError as error:
        if isinstance(error, ExportError):
            raise
        return True


def credential_authorization(value, path, field="authorization"):
    """Separate an HTTP credential from a protocol's prose authorization field.

    Header containers are credential contexts regardless of token length.
    Outside headers, explicit authentication schemes and opaque token-shaped
    scalar values remain sensitive. Ordinary multiword governance prose does
    not become a credential merely because its field is named authorization.
    Strong token/private-key patterns still scan every string independently.
    """
    if not isinstance(value, str) or value.strip().lower() in SAFE_PLACEHOLDERS:
        return False
    ancestors = {part.split("[", 1)[0].lower().replace("-", "_") for part in path.split(".")}
    header_context = bool(ancestors & {"headers", "http_headers", "request_headers", "response_headers"})
    return (header_context or field in {"proxy-authorization", "proxy_authorization"} or
            bool(AUTHORIZATION_SCHEME.match(value)) or
            re.fullmatch(r"[A-Za-z0-9._~+/=-]{16,}", value.strip()) is not None)


def scan(text, label):
    """Inspect gzip-decoded text, nested JSON strings and explicit base64 fields."""
    counts, seen = Counter(), set()
    def string(value, path, depth):
        marker = sha(value.encode())
        if marker in seen:
            return
        seen.add(marker)
        if depth > 24:
            raise ExportError(f"{label}: nested encoding depth exceeded")
        for kind, pattern in SECRET_PATTERNS.items():
            if pattern.search(value):
                raise ExportError(f"{label}: credential-like content ({kind}); field {path}")
        counts["host_path_occurrences"] += len(HOST_PATH.findall(value))
        for match in URL.finditer(value):
            if not public_endpoint(match.group()):
                counts["private_endpoint_occurrences"] += 1
        if value.strip().startswith(("{", "[")):
            try:
                walk(json.loads(value), path, depth + 1)
            except json.JSONDecodeError:
                pass
    def walk(value, path, depth):
        if isinstance(value, dict):
            for key, child in value.items():
                string(str(key), path + ".<key>", depth + 1)
                lower = str(key).lower()
                sensitive = (lower in SECRET_KEYS and lower != "authorization") or (
                    lower in AUTHORIZATION_FIELDS and credential_authorization(child, path, lower))
                if sensitive and isinstance(child, str) and child.lower() not in SAFE_PLACEHOLDERS:
                    raise ExportError(f"{label}: nonempty credential field {path}.{key}")
                if lower == "password" and any(part.lower() in {"credentials", "connection", "auth", "provider", "environment"} for part in path.split(".")):
                    if isinstance(child, str) and child.lower() not in SAFE_PLACEHOLDERS:
                        raise ExportError(f"{label}: host credential password field")
                if lower.endswith("_base64") and isinstance(child, str):
                    try:
                        raw = base64.b64decode(child, validate=True)
                        if raw.startswith(b"\x1f\x8b"):
                            raw = gzip.decompress(raw)
                        string(raw.decode(), path + "." + key + "[decoded]", depth + 1)
                    except ExportError:
                        raise
                    except (ValueError, UnicodeError, OSError):
                        pass
                walk(child, path + "." + str(key), depth + 1)
        elif isinstance(value, list):
            if (len(value) == 2 and isinstance(value[0], str) and value[0].lower() in AUTHORIZATION_FIELDS and
                    credential_authorization(value[1], path, value[0].lower())):
                raise ExportError(f"{label}: credential-bearing HTTP header pair at {path}")
            for index, child in enumerate(value):
                walk(child, path + f"[{index}]", depth + 1)
        elif isinstance(value, str):
            string(value, path, depth)
    string(text, "$", 0)
    for index, line in enumerate(text.splitlines()):
        if line.lstrip().startswith("{"):
            try:
                walk(json.loads(line), f"$line[{index}]", 0)
            except json.JSONDecodeError:
                pass
    return dict(counts)


def redact(text, prefixes, endpoints, mapping):
    changes = Counter()
    local_originals = set()
    def replace(kind, match):
        value = match.group()
        selected = prefixes if kind == "host_path" else endpoints
        if not any(value == prefix or value.startswith(prefix.rstrip("/") + "/") or
                   kind == "host_endpoint" and value.startswith(prefix + "?") for prefix in selected):
            return value
        token = "X6_REDACTED_" + kind.upper() + "_" + sha(value.encode())[:24]
        mapping[token] = {"kind": kind, "original": value}
        local_originals.add(value)
        changes[kind] += 1
        return token
    output = HOST_PATH.sub(lambda match: replace("host_path", match), text)
    output = URL.sub(lambda match: replace("host_endpoint", match), output)
    if output != text:
        def protected(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if (key in INTEGRITY_FIELDS or key.endswith(("context_json", "request_json", "source_proposal_message"))) and isinstance(child, (str, dict, list)):
                        rendered = child if isinstance(child, str) else json.dumps(child)
                        if any(original in rendered for original in local_originals):
                            raise ExportError("Host redaction would change a retained hashed model/context field")
                    protected(child)
            elif isinstance(value, list):
                for child in value:
                    protected(child)
        try:
            protected(json.loads(text))
        except json.JSONDecodeError:
            for line in text.splitlines():
                try:
                    protected(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return output, dict(changes)


def completion(run):
    config_path, result_path = run / "config.json", run / "result.json"
    if not config_path.exists() or not result_path.exists():
        raise ExportError(f"{run.name}: config/result missing; completed job required")
    config, result = json.loads(config_path.read_text()), json.loads(result_path.read_text())
    if isinstance(config.get("cases"), list):
        expected = len(config["cases"]) * len(config["arms"])
        complete = result.get("complete") is True and result.get("observed") == expected
        kind = "main_or_smoke"
    elif isinstance(config.get("units"), list):
        expected = len(config["units"]) * len(config["arms"])
        complete = result.get("completed_records") == expected and result.get("scheduled") == expected
        kind = "natural"
    else:
        raise ExportError(f"{run.name}: unrecognized X6 schedule")
    if not complete:
        raise ExportError(f"{run.name}: run is not recorded complete")
    return {"kind": kind, "scheduled": expected, "config": config}


def walk_files(root):
    for parent, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS and not (Path(parent) / name).is_symlink())
        for name in sorted(filenames):
            path = Path(parent) / name
            if path.is_symlink():
                raise ExportError("Symlinked input files are not exported")
            yield path


def gather(runs, sources, protocols):
    selected, excluded, jobs, names = [], [], [], set()
    for run in sorted(set(path.resolve() for path in runs), key=str):
        info = completion(run)
        name = run.parent.name if run.name == "artifacts" else run.name
        if name in names:
            raise ExportError("Duplicate job namespace")
        names.add(name)
        namespace = "jobs/" + name + "/artifacts"
        jobs.append({"name": name, "namespace": namespace, "scheduled": info["scheduled"], "kind": info["kind"],
                     "config_sha256": sha((run / "config.json").read_bytes()),
                     "registration_sha256": info["config"].get("registration_sha256"),
                     "protocol_sha256": info["config"].get("protocol_sha256"),
                     "manifest_sha256": info["config"].get("manifest_sha256"),
                     "source_hashes": info["config"].get("source_sha256", {})})
        for path in walk_files(run):
            restore = namespace + "/" + path.relative_to(run).as_posix()
            redundant = path.name == "case.json" or path.name.endswith(".json") and path.with_suffix(".json.gz").exists()
            allowed = path.suffix in {".json", ".jsonl", ".gz", ".md", ".txt", ".log", ".stdout", ".stderr"}
            if redundant or not allowed:
                excluded.append({"restore_path": restore, "original_sha256": sha(path.read_bytes()),
                                 "original_bytes": path.stat().st_size, "export_sha256": None,
                                 "reason": "expanded_duplicate_row" if redundant else "outside_evidence_formats"})
            else:
                selected.append((restore, path, "job"))
        excluded.append({"restore_path": namespace + "/inputs/", "reason": "AROS input mirrors excluded without reading",
                         "original_sha256": None, "export_sha256": None})
        for path in walk_files(run):
            if not path.name.endswith(".json.gz"):
                continue
            raw = json.loads(gzip.decompress(path.read_bytes()))
            if isinstance(raw, dict) and raw.get("result", {}).get("policy_calls"):
                if not path.with_suffix("").with_suffix(".policy-journal.jsonl").exists():
                    raise ExportError(f"{name}: raw episode with policy calls lacks matching journal")
    for name, root in sorted(sources.items()):
        if not root.is_dir():
            raise ExportError("Source root must be a directory")
        for path in walk_files(root):
            restore = "sources/" + name + "/" + path.relative_to(root).as_posix()
            if path.suffix in SOURCE_SUFFIXES or path.name == "SHA256SUMS":
                selected.append((restore, path, "source"))
            else:
                excluded.append({"restore_path": restore, "original_sha256": sha(path.read_bytes()),
                                 "original_bytes": path.stat().st_size, "reason": "non-source artifact", "export_sha256": None})
    for name, path in sorted(protocols.items()):
        if not path.is_file():
            raise ExportError("Protocol input must be a file")
        selected.append(("protocols/" + name + path.suffix, path, "protocol"))
    if len({entry[0] for entry in selected}) != len(selected):
        raise ExportError("Duplicate exported artifact path")
    for job in jobs:
        for relative, expected in job["source_hashes"].items():
            candidates = [root / relative for root in sources.values()] + [
                root / "evaluation/sealed_control" / relative for root in sources.values()]
            if not any(path.is_file() and sha(path.read_bytes()) == expected for path in candidates):
                raise ExportError(f"Declared frozen source unavailable or hash differs: {relative}")
        for field in ("registration_sha256", "protocol_sha256"):
            expected = job[field]
            if expected and not any(sha(path.read_bytes()) == expected for path in protocols.values()):
                raise ExportError(f"{field} lacks a matching explicitly supplied protocol")
        if job["manifest_sha256"]:
            candidates = [root / "evaluation/authorship/x2b/manifest-v1.json" for root in sources.values()] + [
                root / "manifest-v1.json" for root in sources.values()]
            if not any(path.is_file() and sha(path.read_bytes()) == job["manifest_sha256"] for path in candidates):
                raise ExportError("Registered cohort manifest missing from explicit source roots")
    return sorted(selected), sorted(excluded, key=lambda row: row["restore_path"]), jobs


def compact_rows(text, path, restore, original_paths):
    """Replace expanded summaries with raw references and unique launcher metadata."""
    if path.name not in {"summary.json", "result.json"}:
        return text, None
    value = json.loads(text)
    if not isinstance(value.get("rows"), list):
        return text, None
    namespace, index = restore.rsplit("/", 1)[0], []
    for row in value["rows"]:
        arm = row.get("x6_arm")
        stem = (row["natural_unit_id"] if row.get("natural_unit_id") else
                str(row.get("case_id")) + "__" + str(row.get("strategy", "direct"))) + "/" + str(arm)
        references = [namespace + "/" + stem + suffix for suffix in (".json.gz", ".failure.json", ".json")]
        reference = next((name for name in references if name in original_paths), None)
        if reference:
            base_path = original_paths[reference]
            base = json.loads(decoded(base_path.read_bytes(), base_path.name))
            if reference.endswith(".json.gz"):
                base = base["result"]
            index.append({"source": reference, "field": "result" if reference.endswith(".json.gz") else None,
                          "overlay": {key: item for key, item in row.items() if key not in base or
                              json.dumps(base[key], sort_keys=True) != json.dumps(item, sort_keys=True)},
                          "remove": [key for key in base if key not in row]})
        else:
            if len(encoded(row)) > 16384:
                raise ExportError("Expanded result row lacks raw evidence")
            index.append({"inline_failure_or_missing": row})
    compact = {"format": "x6-compact-rows-v1", "header": {key: item for key, item in value.items() if key != "rows"},
               "key_order": list(value), "row_index": index}
    return encoded(compact).decode(), "compact_rows"


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def create(args, inspect_only=False):
    sources, protocols = named(args.source), named(args.protocol)
    selected, excluded, jobs = gather(args.runs, sources, protocols)
    for name, path in sorted(named(getattr(args, "file", [])).items()):
        if not path.is_file():
            raise ExportError("Explicit tool/reference input must be a file")
        selected.append(("tools/" + name + path.suffix, path, "source"))
    selected.sort()
    if len({name for name, _, _ in selected}) != len(selected):
        raise ExportError("Duplicate exported explicit file")
    originals = {name: path for name, path, _ in selected}
    report = {"version": VERSION, "completed_jobs": jobs, "selected_files": len(selected),
              "excluded_files": len(excluded), "model_calls": 0}
    mapping, private_originals, entries, origins, counts, public_counts = {}, {}, [], [], Counter(), Counter()
    stage = None
    if not inspect_only:
        out, private = args.out.resolve(), args.private_map.resolve()
        if out.exists() or private.exists():
            raise ExportError("Fresh export and private-map paths required")
        if private.is_relative_to(REPO) or private.is_relative_to(out):
            raise ExportError("Private mapping must remain outside repository/export")
        out.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix="." + out.name + ".staging-", dir=out.parent))
    try:
        for name, path, category in selected:
            safe_relative(name)
            original = path.read_bytes()
            plain = decoded(original, path.name)
            text = plain.decode("utf-8")
            counts.update(scan(text, name))
            compact, recipe = compact_rows(text, path, name, originals) if category == "job" else (text, None)
            public, redactions = redact(compact, args.redact_host_prefix, args.redact_endpoint, mapping)
            public_counts.update(scan(public, name + " exported"))
            public_plain = public.encode()
            changed = public_plain != plain
            materialized = original if not changed else gzip.compress(public_plain, mtime=0) if path.name.endswith(".gz") else public_plain
            compressed = not path.name.endswith(".gz") and len(materialized) >= args.compress_at
            payload = gzip.compress(materialized, mtime=0) if compressed else materialized
            payload_name = "payload/" + name + (".gz" if compressed else "")
            entries.append({"restore_path": name, "payload_path": payload_name, "category": category,
                "original_sha256": sha(original), "original_decoded_sha256": sha(plain), "original_bytes": len(original),
                "export_sha256": sha(payload), "export_bytes": len(payload),
                "materialized_sha256": sha(materialized), "materialized_decoded_sha256": sha(public_plain),
                "storage": "gzip_text" if compressed else "original_format", "recipe": recipe,
                "host_redaction_counts": redactions, "original_bytes_exact": not changed})
            origins.append({"restore_path": name, "original_path": str(path), "original_sha256": sha(original)})
            if redactions or changed and recipe is None:
                private_originals[name] = base64.b64encode(gzip.compress(original, mtime=0)).decode()
            if stage:
                write(stage / payload_name, payload)
        report.update(scan_counts=dict(counts), exported_scan_counts=dict(public_counts),
            host_redacted_files=sum(bool(entry["host_redaction_counts"]) for entry in entries),
            compact_summary_files=sum(entry["recipe"] == "compact_rows" for entry in entries),
            raw_gzip_files=sum(entry["restore_path"].endswith(".json.gz") for entry in entries))
        if inspect_only:
            return report
        if any(sha(Path(origin["original_path"]).read_bytes()) != origin["original_sha256"] for origin in origins):
            raise ExportError("Source changed during packaging")
        private_data = encoded({"private_only": True, "mapping": mapping, "origins": origins,
                                "changed_originals_gzip_base64": private_originals})
        private.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(private_data)
        manifest = {**report, "files": entries, "excluded": excluded,
            "private_mapping_sha256": sha(private_data), "private_mapping_published": False,
            "host_handling": "Only explicit host path/endpoint prefixes are replaced. Numeric data, synthetic identities and scores are preserved. Hashed model/context fields cannot be redacted.",
            "summary_handling": "Expanded rows become raw references plus unique launcher overrides; materialization reconstructs them. Duplicate case/sidecar rows and AROS inputs are omitted.",
            "reproduction": "Materialize, then use included analysis/audit with explicit local frozen/vendor/Python paths. Private-map materialization restores exact originals when original host-bearing source bytes are required."}
        write(stage / "manifest.json", encoded(manifest))
        helper = Path(__file__).read_bytes()
        scan(helper.decode(), "export.py")
        write(stage / "export.py", helper)
        write(stage / "README.md", (
            "# Sealed X6 evidence\n\nRaw episodes and matching policy journals are retained. Original, exported and materialized hashes are separate in manifest.json. AROS inputs and expanded duplicate row archives are omitted.\n\n"
            "Verify:\n\n    python export.py verify --bundle .\n\n"
            "Materialize:\n\n    python export.py materialize --bundle . --out NEW_DIRECTORY\n\n"
            "Optional --private-map restores exact original host-bearing bytes; keep the mapping outside the repository. Public materialization rebuilds compact summaries from raw records and launcher overrides.\n\n"
            "Analysis/native replay use materialized job directories, the explicitly included frozen source/protocol trees and pinned local Python/vendor dependencies. No model calls are required. Detected credentials stop export.\n"
        ).encode())
        write(stage / "bundle-files.json", encoded({"export.py": sha(helper), "README.md": sha((stage / "README.md").read_bytes()),
                                                   "manifest.json": sha((stage / "manifest.json").read_bytes())}))
        for name in ("README.md", "manifest.json", "bundle-files.json"):
            scan((stage / name).read_text(), name)
        verify(stage)
        stage.rename(out)
        stage = None
        return {**report, "out": str(out), "private_mapping_sha256": sha(private_data)}
    finally:
        if stage is not None:
            shutil.rmtree(stage)


def expanded_summary(compact, root):
    rows = []
    for reference in compact["row_index"]:
        if "inline_failure_or_missing" in reference:
            rows.append(reference["inline_failure_or_missing"])
            continue
        path = root / safe_relative(reference["source"])
        value = json.loads(decoded(path.read_bytes(), path.name))
        if reference["field"]:
            value = value[reference["field"]]
        value = {key: item for key, item in value.items() if key not in reference["remove"]}
        value.update(reference["overlay"])
        rows.append(value)
    values = {**compact["header"], "rows": rows}
    return {key: values[key] for key in compact["key_order"]}


def verify(bundle, out=None, private_path=None):
    bundle = bundle.resolve()
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name, expected in json.loads((bundle / "bundle-files.json").read_text()).items():
        if sha((bundle / safe_relative(name)).read_bytes()) != expected:
            raise ExportError("Bundle helper/manifest hash mismatch")
    private = None
    if private_path:
        data = private_path.read_bytes()
        if sha(data) != manifest["private_mapping_sha256"]:
            raise ExportError("Private-map hash mismatch")
        private = json.loads(data)
    if out:
        out = out.resolve()
        if out.exists():
            raise ExportError("Materialization destination must be new")
        out.mkdir(parents=True)
    delayed, checks = [], []
    for entry in manifest["files"]:
        payload = (bundle / safe_relative(entry["payload_path"])).read_bytes()
        if sha(payload) != entry["export_sha256"]:
            raise ExportError("Exported artifact hash mismatch")
        materialized = gzip.decompress(payload) if entry["storage"] == "gzip_text" else payload
        if sha(materialized) != entry["materialized_sha256"]:
            raise ExportError("Materialized artifact hash mismatch")
        plain = decoded(materialized, entry["restore_path"])
        if sha(plain) != entry["materialized_decoded_sha256"]:
            raise ExportError("Decoded artifact hash mismatch")
        scan(plain.decode(), entry["restore_path"])
        original_mode = private is not None and entry["restore_path"] in private["changed_originals_gzip_base64"]
        if original_mode:
            materialized = gzip.decompress(base64.b64decode(private["changed_originals_gzip_base64"][entry["restore_path"]], validate=True))
            if sha(materialized) != entry["original_sha256"]:
                raise ExportError("Private original hash mismatch")
        if out:
            target = out / safe_relative(entry["restore_path"])
            write(target, materialized)
            if entry["recipe"] == "compact_rows" and not original_mode:
                delayed.append(target)
        checks.append({"restore_path": entry["restore_path"], "written_sha256": sha(materialized),
                       "original_bytes_exact": sha(materialized) == entry["original_sha256"]})
    if out:
        originals = {entry["restore_path"]: entry["original_sha256"] for entry in manifest["files"]}
        for path in delayed:
            restored = encoded(expanded_summary(json.loads(path.read_text()), out))
            path.write_bytes(restored)
            for row in checks:
                if out / row["restore_path"] == path:
                    row.update(written_sha256=sha(restored), original_bytes_exact=sha(restored) == originals[row["restore_path"]])
        write(out / "materialization-receipt.json", encoded({"passed": True, "files": checks, "model_calls": 0}))
    return {"passed": True, "artifact_files_verified": len(checks), "model_calls": 0, "materialized": str(out) if out else None}


def self_test():
    with tempfile.TemporaryDirectory(prefix="x6-export-test-") as temporary:
        root = Path(temporary)
        run = root / "job" / "artifacts"
        episode = run / "banking__user_task_1__injection_task_0__direct"
        episode.mkdir(parents=True)
        result = {"case_id": "banking__user_task_1__injection_task_0", "x6_arm": "sealed_exact", "strategy": "direct",
                  "status": "model_round_limit", "native_targeted_asr": True, "policy_calls": [{"ok": True}],
                  "numeric": 200.29, "synthetic_account": "US133000000121212121212", "package_version": "4.15.3.0"}
        raw = gzip.compress(json.dumps({"result": result, "initial": {"password": "password123"}}).encode(), mtime=0)
        (episode / "sealed_exact.json.gz").write_bytes(raw)
        (episode / "sealed_exact.json").write_bytes(encoded(result))
        (episode / "sealed_exact.policy-journal.jsonl").write_text(json.dumps({"stage": "policy_response", "response": {"text": "fixture"}}) + "\n")
        (episode / "sealed_exact.stderr").write_text("Known launcher diagnostic.\n")
        (episode / "case.json").write_bytes(encoded({"arms": {"sealed_exact": result}}))
        (run / "config.json").write_bytes(encoded({"cases": [{"case_id": result["case_id"], "role": "attack", "strategy": "direct"}],
            "arms": ["sealed_exact"], "source_sha256": {}, "manifest": "/data/private-fixture/manifest.json"}))
        (run / "result.json").write_bytes(encoded({"complete": True, "observed": 1, "scheduled_episodes": 1}))
        (run / "summary.json").write_bytes(encoded({"complete": True, "rows": [result]}))
        (run / "inputs").mkdir()
        (run / "inputs/ignored-secret.json").write_text(json.dumps({"api_key": "sk-" + "X" * 32}))
        natural = root / "natural-job/artifacts"
        natural_episode = natural / "source-fixture"
        natural_episode.mkdir(parents=True)
        natural_row = {**result, "natural_unit_id": "source-fixture", "policy_calls": []}
        (natural_episode / "sealed_exact.json.gz").write_bytes(gzip.compress(json.dumps({"result": natural_row}).encode(), mtime=0))
        launcher_rows = [{**natural_row, "status": "operationally_unknown", "launcher_exit_code": "timeout", "launcher_elapsed_s": 12.5},
                         {"natural_unit_id": "source-fixture", "x6_arm": "originalauto", "status": "operationally_unknown", "launcher_error": "launch_error"}]
        (natural / "config.json").write_bytes(encoded({"units": ["source-fixture"], "arms": ["sealed_exact", "originalauto"]}))
        natural_result = {"scheduled": 2, "completed_records": 2, "rows": launcher_rows, "historical_vs_new_costs": "fixture"}
        (natural / "result.json").write_bytes(encoded(natural_result))
        args = argparse.Namespace(runs=[run, natural], source=[], protocol=[], out=root / "bundle", private_map=root / "private.json",
                                  redact_host_prefix=["/data/private-fixture"], redact_endpoint=[], compress_at=32)
        report = create(args)
        assert report["raw_gzip_files"] == 2 and report["compact_summary_files"] == 2
        manifest = json.loads((args.out / "manifest.json").read_text())
        raw_entry = next(row for row in manifest["files"] if row["restore_path"].endswith("sealed_exact.json.gz"))
        assert raw_entry["original_bytes_exact"] and raw_entry["export_sha256"] == sha(raw)
        verify(args.out, root / "public")
        restored = root / "public/jobs/job/artifacts"
        assert json.loads((restored / "summary.json").read_text())["rows"] == [result]
        assert not (restored / "inputs").exists()
        assert json.loads((restored / "config.json").read_text())["manifest"].startswith("X6_REDACTED")
        assert json.loads((root / "public/jobs/natural-job/artifacts/result.json").read_text()) == natural_result
        verify(args.out, root / "original", args.private_map)
        assert (root / "original/jobs/job/artifacts/config.json").read_bytes() == (run / "config.json").read_bytes()
        assert (restored / "banking__user_task_1__injection_task_0__direct/sealed_exact.policy-journal.jsonl").read_bytes() == (episode / "sealed_exact.policy-journal.jsonl").read_bytes()
        secrets = [json.dumps({"api_key": "sk-" + "Q" * 32}), json.dumps({"nested": json.dumps({"access_token": "not-a-placeholder"})}),
                   json.dumps({"payload_base64": base64.b64encode(json.dumps({"client_secret": "private-fixture"}).encode()).decode()})]
        for secret in secrets:
            try:
                scan(secret, "fixture")
            except ExportError:
                pass
            else:
                raise AssertionError("credential scan failed")
        governance = {"authorization": "Root registers frozen protocol and all model-calling inputs before launch. Implementation and loopback fixture qualification make zero model calls."}
        scan(json.dumps(governance), "registered_protocol_authorization")
        scan(json.dumps({"nested": json.dumps(governance)}), "nested_protocol_authorization")
        basic = "Basic " + base64.b64encode(b"fixture-user:fixture-private").decode()
        authorization_credentials = [
            json.dumps({"authorization": basic}),
            json.dumps({"authorization": "Bearer " + "short-token"}),
            json.dumps({"authorization": "opaque" + "7" * 30}),
            json.dumps({"request": {"headers": {"Authorization": "short-secret"}}}),
            json.dumps({"http_headers": [["Authorization", "short-secret"]]}),
            "Authorization: " + basic,
            json.dumps({"authorization": governance["authorization"] + " sk-" + "Q" * 32}),
        ]
        for secret in authorization_credentials:
            try:
                scan(secret, "authorization_regression")
            except ExportError:
                pass
            else:
                raise AssertionError("HTTP authorization credential scan failed")
        opaque_id = "resp_" + "A" * 159 + "|-" + "sk-" + "B" * 336
        old_token_pattern = re.compile(r"\b(?:gh[pousr]_|github_pat_|hf_|sk-)[A-Za-z0-9_-]{20,}\b")
        assert len(opaque_id) == 505 and len(old_token_pattern.search(opaque_id).group()) == 339
        scan(json.dumps({"context": {"messages": [{"role": "assistant", "responseId": opaque_id}]}}), "opaque_response_identifier")
        scan(json.dumps({"context_json": json.dumps({"messages": [{"responseId": opaque_id}]})}), "nested_opaque_response_identifier")
        lexical_credentials = [
            json.dumps({"responseId": "sk-" + "B" * 336}),
            "Saved credential: " + "sk-" + "B" * 336 + ".",
            json.dumps({"api_key": opaque_id}),
            json.dumps({"headers": {"Authorization": opaque_id}}),
            "Authorization: Bearer " + opaque_id,
            json.dumps({"authorization": "Bearer " + opaque_id}),
        ]
        for secret in lexical_credentials:
            try:
                scan(secret, "token_boundary_regression")
            except ExportError:
                pass
            else:
                raise AssertionError("Standalone or credential-context token was missed")
        scan(json.dumps({"user_account": {"password": "new_password"}, "number": 200.29, "version": "4.15.3.0"}), "synthetic")
        try:
            redact(json.dumps({"context_json": json.dumps({"path": "/data/private-fixture/value"})}), ["/data/private-fixture"], [], {})
        except ExportError:
            pass
        else:
            raise AssertionError("hashed context must not be redacted")
    return {"passed": True, "checks": ["raw_gzip_exact", "journal_exact_materialization", "compact_rows_reconstructed",
        "AROS_inputs_not_read_or_copied", "host_mapping_private_and_reversible", "numeric_synthetic_data_preserved",
        "decoded_nested_credentials_blocked", "hashed_context_redaction_blocked", "natural_launcher_overrides_and_missing_raw_failure_retained",
        "governance_authorization_prose_allowed", "HTTP_Bearer_Basic_opaque_and_nested_header_credentials_blocked",
        "opaque_response_id_embedded_substring_not_a_standalone_token", "standalone_and_credential_contexts_still_blocked"], "model_calls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "build"):
        command = sub.add_parser(name)
        command.add_argument("--runs", type=Path, nargs="+", required=True)
        command.add_argument("--source", action="append", default=[], metavar="NAME=PATH")
        command.add_argument("--protocol", action="append", default=[], metavar="NAME=PATH")
        command.add_argument("--file", action="append", default=[], metavar="NAME=PATH",
                             help="Explicit analysis/audit/export or reference file; avoids copying active work trees")
        command.add_argument("--redact-host-prefix", action="append", default=[])
        command.add_argument("--redact-endpoint", action="append", default=[])
        command.add_argument("--compress-at", type=int, default=128 * 1024)
        if name == "build":
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--private-map", type=Path, required=True)
    for name in ("verify", "materialize"):
        command = sub.add_parser(name)
        command.add_argument("--bundle", type=Path, required=True)
        if name == "materialize":
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--private-map", type=Path)
    sub.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            result = self_test()
        elif args.command in {"inspect", "build"}:
            result = create(args, inspect_only=args.command == "inspect")
        else:
            result = verify(args.bundle, getattr(args, "out", None), getattr(args, "private_map", None))
        print(json.dumps(result, indent=2, sort_keys=True))
    except ExportError as error:
        parser.exit(2, "Export stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
