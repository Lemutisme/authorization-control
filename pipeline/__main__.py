"""Authorization Control research pipeline."""

import argparse
import json
import os
import subprocess
import sys
import venv
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def setup():
    target = ROOT / ".venv"
    if (target / "bin/python").exists():
        version = subprocess.check_output(
            [str(target / "bin/python"), "-c", 'import sys; print("%s.%s"%sys.version_info[:2])'],
            text=True,
        ).strip()
        if version != "3.13":
            backup = ROOT / ".venv-previous"
            if backup.exists():
                raise RuntimeError(
                    "Existing environment has the wrong Python version; move .venv before setup"
                )
            target.rename(backup)
    if not (target / "bin/python").exists():
        if shutil.which("uv"):
            subprocess.run(["uv", "venv", "--python", "3.13", str(target)], check=True)
        elif sys.version_info[:2] == (3, 13):
            venv.EnvBuilder(with_pip=False).create(target)
        else:
            raise RuntimeError(
                "Python 3.13 is required; install it or install uv to manage the research environment"
            )
    python = target / "bin/python"
    if shutil.which("uv"):
        installer = ["uv", "pip", "install", "--python", str(python)]
    else:
        installer = [sys.executable, "-m", "pip", "--python", str(python), "install"]
    subprocess.run([*installer, "-r", str(ROOT / "requirements.txt")], check=True)
    progent = ROOT / ".deps/progent"
    pin = "b02783b896d4bf01a2adf24738015e258db8d35b"
    if not (progent / ".git").exists():
        progent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(progent)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(progent),
                "remote",
                "add",
                "origin",
                "https://github.com/sunblaze-ucb/progent.git",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(progent), "fetch", "--depth=1", "origin", pin], check=True)
        subprocess.run(
            ["git", "-C", str(progent), "checkout", "--detach", "FETCH_HEAD"], check=True
        )
    if (
        subprocess.check_output(["git", "-C", str(progent), "rev-parse", "HEAD"], text=True).strip()
        != pin
    ):
        raise RuntimeError("Progent dependency revision differs from the required pin")
    print("Research environment ready. Run .venv/bin/python -m pipeline reproduce --all")


def reproduce(out, native=True):
    from .integrity import verify

    print("Verified", verify(), "source and data files.", flush=True)
    from . import recorded, history

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    norm, base, strict = recorded.metric_helpers()
    stages = {
        "faults": lambda: recorded.fault_injection(base),
        "matched": lambda: recorded.matched_inputs(norm, base),
        "models": lambda: recorded.models(strict),
        "history": history.analyze,
    }
    for name, run in stages.items():
        print("Analyzing " + name, flush=True)
        value = run()
        (out / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")
    if native:
        from .native import replay_archive, replay_models

        for archive, name in [
            ("fault-injection.jsonl.xz", "faults"),
            ("matched-inputs.jsonl.xz", "matched"),
            ("paper-studies.jsonl.xz", "history"),
        ]:
            report = replay_archive(archive, out / ("native-" + name + ".json"))
            if report["failures"]:
                raise RuntimeError("Native replay failed: " + name)
        report = replay_models(out / "native-models.json")
        if report["failures"]:
            raise RuntimeError("Native replay failed: models")
        from .policies import replay as replay_policies

        replay_policies(out)
    from .report import build

    build(out)
    print("Reproduction complete: " + str(out.resolve()), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="Install the pinned research dependencies in .venv")
    p = sub.add_parser(
        "prepare", help="Materialize the recorded inputs and pinned experiment sources"
    )
    p.add_argument("--force", action="store_true")
    p = sub.add_parser(
        "reproduce", help="Recompute all tables, replay native effects and produce figures"
    )
    p.add_argument("--all", action="store_true")
    p.add_argument("--out", type=Path, default=ROOT / "results")
    p.add_argument("--analysis-only", action="store_true")
    p = sub.add_parser("run", help="Launch fresh model experiments")
    p.add_argument("--study", default="all")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--plan", action="store_true")
    p = sub.add_parser("replay", help="Replay one or all retained episode archives")
    p.add_argument("--study", choices=["all", "faults", "matched", "history"], default="all")
    p.add_argument("--out", type=Path, default=ROOT / "results")
    p = sub.add_parser("figures", help="Generate figures and tables from recomputed results")
    p.add_argument("--out", type=Path, default=ROOT / "results")
    p = sub.add_parser("list", help="List the complete experiment schedules")
    args = parser.parse_args()
    if args.command == "setup":
        setup()
    elif args.command == "prepare":
        from .prepare import prepare

        print(prepare(args.force))
    elif args.command == "reproduce":
        reproduce(args.out, not args.analysis_only)
    elif args.command == "run":
        from .launch import launch

        launch(args.study, args.out, args.plan)
    elif args.command == "replay":
        from .native import replay_archive

        for name, archive in [
            ("faults", "fault-injection.jsonl.xz"),
            ("matched", "matched-inputs.jsonl.xz"),
            ("history", "paper-studies.jsonl.xz"),
        ]:
            if args.study in {"all", name}:
                report = replay_archive(archive, args.out / ("native-" + name + ".json"))
                if report["failures"]:
                    raise SystemExit(1)
    elif args.command == "figures":
        from .report import build

        build(args.out)
    else:
        from .launch import recipes
        from collections import Counter

        for name, count in Counter(r["study"] for r in recipes("all")).items():
            print(name, count, "runs")


if __name__ == "__main__":
    main()
