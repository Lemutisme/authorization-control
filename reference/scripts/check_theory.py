#!/usr/bin/env python3
"""Kernel-check the small Lean logic artifact, not a production implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--lean',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True);args=parser.parse_args()
    args.work.mkdir(parents=True,exist_ok=False)
    source=ROOT/'theory/RecoveryAuthorization.lean';source_bytes=source.read_bytes();text=source_bytes.decode()
    if re.search(r'\b(sorry|admit|native_decide|unsafe)\b',text):raise ValueError('Unapproved proof escape/placeholder in source.')
    if re.search(r'^\s*(axiom|opaque)\b',text,re.M):raise ValueError('Project axiom/opaque declaration in source.')
    frozen=args.work/source.name;frozen.write_bytes(source_bytes)
    lean=args.lean.resolve()
    version=subprocess.run([str(lean),'--version'],capture_output=True,text=True,check=True).stdout.strip()
    command=[str(lean),'-o',str(args.work/'RecoveryAuthorization.olean'),str(frozen)]
    result=subprocess.run(command,cwd=args.work,capture_output=True,text=True)
    output=result.stdout+result.stderr;(args.work/'lean-output.txt').write_text(output)
    names=re.findall(r'^theorem\s+(\w+)',text,re.M)
    report={'kind':'Lean verification of parameterized logical statements, not empirical defense efficacy',
            'lean_version':version,'source':'theory/RecoveryAuthorization.lean',
            'source_sha256':hashlib.sha256(frozen.read_bytes()).hexdigest(),
            'exit_code':result.returncode,'theorems':names,'theorem_count':len(names),
            'proof_output_sha256':hashlib.sha256(output.encode()).hexdigest(),
            'axiom_reports':[line for line in output.splitlines() if 'axioms' in line or 'depends on axioms' in line],
            'limits':['World/policy/compatibility functions are parameters; their adequacy to deployment is not formalized.',
                      'The effect-correspondence bridge and actual commit-world inclusion are assumptions.',
                      'The finite classifier requires decidable predicates and explicit enumeration coverage; it is not a deployment collector.',
                      'No runtime profile extraction, concrete provider, isolation, budget or liveness proof.',
                      'No attack benchmark or recovery-agent experiment was run by this check.']}
    (args.work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(output,end='');print(json.dumps({'exit_code':result.returncode,'theorem_count':len(names),'source_sha256':report['source_sha256']},indent=2))
    if result.returncode or 'sorryAx' in output:raise SystemExit(1)
    if len(report['axiom_reports'])!=len(names):raise RuntimeError('Not every theorem has an axiom report.')
    if source.read_bytes()!=source_bytes:raise RuntimeError('Source changed during proof check; retained frozen result is not installed.')
    shutil.copyfile(args.work/'result.json',ROOT/'theory/verification.json')

if __name__=='__main__':main()
