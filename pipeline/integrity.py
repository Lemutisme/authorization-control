"""Verify the delivered source and data files before running experiments."""

import hashlib
import json
from .paths import ROOT


def verify():
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    for record in manifest["files"]:
        path = (ROOT / record["path"]).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("Manifest path escapes the repository")
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("Source/data checksum mismatch: " + record["path"])
    return len(manifest["files"])
