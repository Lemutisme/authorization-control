"""Owned AROS launch; the CLI retains its native identity and approval controls."""
from pipeline.paths import resolve as research_path
from pathlib import Path
import os, subprocess, sys
phase = sys.argv[1]
assert phase in {'pilot', 'main'}
root = Path(research_path('external/812f263b19c4/sp27-two-channel-20261113'))
frozen = root / 'frozen-v1'
name = 'two-channel-' + phase + '-v1'
cmd = ['python3', '-B', research_path('external/04516917b4e0/aros_prepare180.py'), 'run', 'start', '--name', name, '--question', 'codex-01a193cf-3c5a-7b81-a001-15dfe133f832--two-channel-factorial.md', '--predict', 'codex-01a193cf-3c5a-7b81-a001-15dfe133f832--two-channel-prediction.md', '--obligation', 'goal186', '--memory', '16']
if phase == 'main':
    cmd += ['--main', '--after', 'two-channel-pilot-v1']
paths = {p for p in frozen.rglob('*') if p.is_file()}
for tree in [research_path('experiments/sealed'), research_path('experiments/natural')]:
    paths.update((p for p in Path(tree).rglob('*') if p.is_file() and p.suffix in {'.py', '.mjs'} and ('node_modules' not in p.parts)))
paths.update([Path(__file__).resolve(), Path(research_path('external/04516917b4e0/aros_prepare180.py'))])
for p in sorted(paths):
    cmd += ['--input', str(p)]
for reference in [research_path('experiments/sealed'), research_path('experiments/natural'), research_path('python-environment'), research_path('dependencies'), research_path('progent'), research_path('experiments/shared/evaluation/pi/node_modules')]:
    cmd += ['--reference', reference]
cmd += ['--', research_path('python'), '-B', str(frozen / 'runtime/run.py'), '--protocol', str(frozen / f'protocol-{phase}.json'), '--registration', str(frozen / 'registration.json'), '--campaign', name, '--coupling-root', str(root / 'coupling'), '--out', str(root / 'outputs' / f'{phase}-v1'), '--workers', '3' if phase == 'pilot' else '6']
env = {**os.environ, 'CUDA_VISIBLE_DEVICES': '', 'ENABLE_SECAGENT': 'True', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '20261106', 'BASELINE_VENDOR': research_path('dependencies'), 'PROGENT_SOURCE': research_path('progent')}
raise SystemExit(subprocess.run(cmd, env=env).returncode)
