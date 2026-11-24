"""Reconstruct the original policy lifecycles and execute both conditional probes."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from .launch import environment
from .paths import workspace
from .prepare import prepare


def replay(output):
    prepare()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="policy-replay-", dir=output))
    reports = {}
    for name, entry in [
        ("post", "control_boundary/replay.py"),
        ("initial", "refinement_initial/initial.py"),
    ]:
        target = folder / name
        env = environment(target)
        env.update(
            PGA_API_BASE_URL="https://offline.invalid/v1",
            PGA_API_KEY="offline",
            OPENAI_API_KEY="offline",
        )
        argv = [
            sys.executable,
            "-B",
            str(workspace() / "experiments/shared/evaluation" / entry),
            "--job",
            str(workspace() / "runs/strong-banking-main-v1"),
            "--frozen",
            str(workspace() / "experiments/lifecycles"),
            "--out",
            str(target),
        ]
        if name == "post":
            argv += ["--phase", "main"]
        else:
            argv += ["--post-exposure", str(folder / "post")]
        with (folder / (name + ".log")).open("w") as log:
            result = subprocess.run(
                argv, env=env, cwd=workspace(), stdout=log, stderr=subprocess.STDOUT
            )
        if result.returncode:
            raise RuntimeError("Policy replay failed; see " + str(folder / (name + ".log")))
        reports[name] = json.loads((target / "result.json").read_text())
        assert (
            reports[name]["replay_failures"] == 0
            and reports[name]["model_requests"] == reports[name]["network_requests"] == 0
        )
    assert reports["post"]["qualified"] == 98 and reports["post"]["progent_admitted"] == 1
    assert (
        reports["initial"]["qualified_initial_candidates"] == 112
        and reports["initial"]["initial_progent_admitted_qualified"] == 7
    )
    (output / "native-policy-lifecycles.json").write_text(json.dumps(reports, indent=2) + "\n")
    return reports
