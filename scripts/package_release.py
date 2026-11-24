#!/usr/bin/env python3
"""Build the installable runtime and complete source release from a clean commit."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, default=ROOT / "dist")
args = parser.parse_args()
for command in [["git", "diff", "--quiet"], ["git", "diff", "--cached", "--quiet"]]:
    if subprocess.run(command, cwd=ROOT).returncode:
        raise SystemExit("Commit the validated source before building a release")
metadata = json.loads((ROOT / "package.json").read_text())
version = metadata["version"]
output = args.out.resolve()
output.mkdir(parents=True, exist_ok=True)
package = json.loads(
    subprocess.check_output(
        ["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(output)],
        cwd=ROOT,
        text=True,
    )
)[0]
archive = output / ("authorization-control-" + version + ".zip")
subprocess.run(
    [
        "git",
        "archive",
        "--format=zip",
        "--prefix=authorization-control-" + version + "/",
        "--output",
        str(archive),
        "HEAD",
    ],
    cwd=ROOT,
    check=True,
)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
files = [output / package["filename"], archive]
record = {
    "version": version,
    "commit": commit,
    "files": [
        {
            "name": p.name,
            "bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        }
        for p in files
    ],
}
(output / "release.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
