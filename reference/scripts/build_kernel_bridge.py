#!/usr/bin/env python3
"""Compile the real ProContract reducer in an isolated offline Cargo workspace.
Reads a supplied Git checkout; does not edit it or copy it into this repository.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PIN='428f316fe5072cdaf548a603298d09c4374713d7'
FILES=['lib.rs','command.rs','digest.rs','model.rs','rejection.rs','transition.rs']

def main():
    p=argparse.ArgumentParser();p.add_argument('--procontract',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True)
    p.add_argument('--cargo-home',type=Path,required=True);p.add_argument('--rustup-home',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    kernel=a.out/'kernel';(kernel/'src').mkdir(parents=True)
    bridge=a.out/'bridge';(bridge/'src').mkdir(parents=True)
    sources=[]
    for name in FILES:
        relative='codex-rs/pro-contract/src/'+name
        data=subprocess.run(['git','-C',str(a.procontract),'show',PIN+':'+relative],capture_output=True,check=True).stdout
        (kernel/'src'/name).write_bytes(data)
        sources.append({'path':relative,'sha256':hashlib.sha256(data).hexdigest()})
    # Preserve original crate manifest; supply the inherited workspace configuration.
    data=subprocess.run(['git','-C',str(a.procontract),'show',PIN+':codex-rs/pro-contract/Cargo.toml'],capture_output=True,check=True).stdout
    (kernel/'Cargo.toml').write_bytes(data)
    license_data=subprocess.run(['git','-C',str(a.procontract),'show',PIN+':LICENSE'],capture_output=True,check=True).stdout
    (a.out/'LICENSE.procontract').write_bytes(license_data)
    (a.out/'Cargo.toml').write_text('''[workspace]
members = ["kernel", "bridge"]
resolver = "3"
[workspace.package]
version = "0.0.0"
edition = "2024"
license = "Apache-2.0"
[workspace.lints]
[workspace.dependencies]
serde = { version = "1", features = ["rc"] }
serde_json = "1"
sha2 = "0.10"
thiserror = "2.0.17"
pretty_assertions = "1.4.1"
''')
    (bridge/'Cargo.toml').write_text('''[package]
name = "safecontract-kernel-bridge"
version = "0.0.0"
edition = "2024"
[dependencies]
codex-pro-contract = { path = "../kernel" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
''')
    source=Path(__file__).resolve().parents[1]/'prototype/kernel_bridge.rs'
    shutil.copyfile(source,bridge/'src/main.rs')
    env=dict(os.environ);env.update(CARGO_HOME=str(a.cargo_home),RUSTUP_HOME=str(a.rustup_home),RUSTUP_TOOLCHAIN='1.95.0')
    cmd=[str(a.cargo),'build','--offline','--manifest-path',str(a.out/'Cargo.toml'),'-p','safecontract-kernel-bridge','--jobs','2']
    subprocess.run(cmd,env=env,check=True)
    binary=a.out/'target/debug/safecontract-kernel-bridge'
    metadata={'source_commit':PIN,'source_files':sources,'core_source_changed':False,
              'bridge_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'cargo_lock_sha256':hashlib.sha256((a.out/'Cargo.lock').read_bytes()).hexdigest(),
              'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
              'scope':'Actual reducer only, not the original production store/harness. Offline local qualification.'}
    (a.out/'build-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(binary)

if __name__=='__main__':main()
