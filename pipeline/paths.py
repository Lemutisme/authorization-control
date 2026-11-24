"""Portable locations shared by the pinned experiment runners."""

import importlib.util
import os
import site
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "research"
DATA = RESEARCH / "data"
EXPERIMENTS = RESEARCH / "experiments"
INPUTS = RESEARCH / "inputs"


def workspace():
    return Path(os.environ.get("AC_WORKSPACE", ROOT / ".work")).resolve()


def resolve(resource):
    resource = str(resource).removeprefix("repo://")
    if resource == "python":
        return sys.executable
    if "/node_modules" in resource:
        base = (ROOT / "node_modules").resolve()
        suffix = resource.split("/node_modules", 1)[1].lstrip("/")
        target = (base / suffix).resolve()
        if not target.is_relative_to(base):
            raise ValueError("Dependency resource escapes node_modules")
        return str(target)
    if resource == "python-environment":
        return sys.prefix
    if resource == "dependencies" or resource.startswith("dependencies/"):
        return (
            str(Path(site.getsitepackages()[0]) / resource.removeprefix("dependencies/"))
            if resource != "dependencies"
            else site.getsitepackages()[0]
        )
    if resource == "progent" or resource.startswith("progent/"):
        if os.environ.get("PROGENT_SOURCE"):
            base = Path(os.environ["PROGENT_SOURCE"]).resolve()
        elif (ROOT / ".deps/progent/.git").exists():
            base = ROOT / ".deps/progent"
        else:
            spec = importlib.util.find_spec("secagent")
            if spec is None:
                raise RuntimeError(
                    "Install the research dependencies with python -m pipeline setup"
                )
            base = Path(spec.origin).resolve().parent.parent
        return str(base / resource.removeprefix("progent/")) if resource != "progent" else str(base)
    path = (workspace() / resource).resolve()
    if not path.is_relative_to(workspace()):
        raise ValueError("Resource escapes the experiment workspace")
    return str(path)


def relocate(value):
    if isinstance(value, str):
        return resolve(value) if value.startswith("repo://") else value
    if isinstance(value, list):
        return [relocate(x) for x in value]
    if isinstance(value, dict):
        return {relocate(k): relocate(v) for k, v in value.items()}
    return value
