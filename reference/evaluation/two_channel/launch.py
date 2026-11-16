"""Owned AROS launch; the CLI retains its native identity and approval controls."""
from pathlib import Path
import os, subprocess, sys

phase = sys.argv[1]
assert phase in {'pilot', 'main'}
root = Path('/artifact-source/812f263b19c4/sp27-two-channel-20261113')
frozen = root / 'frozen-v1'
name = 'two-channel-' + phase + '-v1'
cmd = ['python3', '-B', '/artifact-source/04516917b4e0/aros_prepare180.py',
       'run', 'start', '--name', name,
       '--question', 'codex-01a193cf-3c5a-7b81-a001-15dfe133f832--two-channel-factorial.md',
       '--predict', 'codex-01a193cf-3c5a-7b81-a001-15dfe133f832--two-channel-prediction.md',
       '--obligation', 'goal186', '--memory', '16']
if phase == 'main':
    cmd += ['--main', '--after', 'two-channel-pilot-v1']
paths = {p for p in frozen.rglob('*') if p.is_file()}
for tree in ['/artifact-source/eacb584555c5/frozen-v1',
             '/artifact-source/b24eb20cebce/natural-frozen-v1']:
    paths.update(p for p in Path(tree).rglob('*') if p.is_file()
                 and p.suffix in {'.py', '.mjs'} and 'node_modules' not in p.parts)
paths.update([Path(__file__).resolve(), Path('/artifact-source/04516917b4e0/aros_prepare180.py')])
for p in sorted(paths):
    cmd += ['--input', str(p)]
for reference in ['/artifact-source/eacb584555c5/frozen-v1',
                  '/artifact-source/b24eb20cebce/natural-frozen-v1',
                  '/artifact-source/398180b38ed7/venv',
                  '/artifact-source/3d9fa19e91e5/vendor',
                  '/artifact-source/c4751a2fc0fe/progent',
                  '/artifact-source/ec5d02833076/node_modules']:
    cmd += ['--reference', reference]
cmd += ['--', '/artifact-source/01b8ea88deeb/python', '-B',
        str(frozen/'runtime/run.py'), '--protocol', str(frozen/f'protocol-{phase}.json'),
        '--registration', str(frozen/'registration.json'), '--campaign', name,
        '--coupling-root', str(root/'coupling'), '--out', str(root/'outputs'/f'{phase}-v1'),
        '--workers', '3' if phase == 'pilot' else '6']
env = {**os.environ, 'CUDA_VISIBLE_DEVICES': '', 'ENABLE_SECAGENT': 'True',
       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '20261106',
       'BASELINE_VENDOR': '/artifact-source/3d9fa19e91e5/vendor',
       'PROGENT_SOURCE': '/artifact-source/c4751a2fc0fe/progent'}
raise SystemExit(subprocess.run(cmd, env=env).returncode)
