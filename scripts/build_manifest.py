#!/usr/bin/env python3
"""Rewrite MANIFEST.json from the files tracked by git.

The manifest lists every tracked file except itself with its size and SHA-256.
`python -m pipeline reproduce` checks the working tree against it before any
analysis, so run this after adding, moving or editing a tracked file.
"""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.json"


def tracked_files():
    listing = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    paths = (name for name in listing.decode().split("\0") if name)
    return sorted(name for name in paths if name != MANIFEST.name and (ROOT / name).is_file())


def main():
    version = json.loads((ROOT / "package.json").read_text())["version"]
    files = []
    for name in tracked_files():
        content = (ROOT / name).read_bytes()
        files.append({"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    MANIFEST.write_text(json.dumps({"format": 1, "version": version, "files": files}, indent=2) + "\n")
    print(f"MANIFEST.json: {len(files)} files, version {version}")


if __name__ == "__main__":
    main()
