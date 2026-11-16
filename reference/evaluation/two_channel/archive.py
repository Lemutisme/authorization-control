"""Archive the completed study in the private research checkout; no publication."""
from pathlib import Path
import gzip, hashlib, json, shutil, tarfile

source = Path('/artifact-source/812f263b19c4/sp27-two-channel-20261113')
work = Path('/artifact-source/f42cba29ab74/two-channel-20261113')
dest = Path('/artifact-source/6a55f9f127d3/two_channel')
main = json.loads((source/'outputs/main-v1/result.json').read_text())
assert main['complete'] and main['observed'] == main['scheduled'] == 816
assert not dest.exists(), 'Archive is immutable; choose a new revision rather than overwrite'
dest.mkdir(parents=True)
for name in ['frozen-v1', 'analysis-source-v1', 'analysis-main']:
    shutil.copytree(source/name, dest/name)
for name in ['native_audit', 'outside-review']:
    if (work/name).exists():
        shutil.copytree(work/name, dest/name,
                        ignore=shutil.ignore_patterns('__pycache__', 'main-v1', 'main-v2'))
        for revision in ['main-v1', 'main-v2']:
            if (work/name/revision).exists():
                with tarfile.open(dest/name/(revision+'.tar.gz'),'w:gz') as archive:
                    archive.add(work/name/revision,arcname=revision)
for name in ['README.md','question.md','idea.md','prediction.md','prepare_protocol.py','launch.py','audit_inputs.py','archive.py','paper-plan.md']:
    if (work/name).exists(): shutil.copy2(work/name,dest/name)
for name in ['pilot-operational-readback.json','pilot-input-audit.json','main-input-audit.json','main-native-audit.json','cost-summary.json','main-supervisor-readback.json']:
    if (source/name).exists(): shutil.copy2(source/name,dest/name)
for phase in ['pilot-v1','main-v1']:
    out = source/'outputs'/phase
    for name in ['config.json','progress.json','status.md']:
        if (out/name).exists():
            target=dest/'outputs'/phase/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(out/name,target)
    with gzip.open(dest/'outputs'/phase/'result.json.gz','wb',compresslevel=6) as f:
        f.write((out/'result.json').read_bytes())
    for raw in out.glob('*/repetition-*/*.json.gz'):
        target=dest/'outputs'/phase/raw.relative_to(out);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(raw,target)
    with tarfile.open(dest/'outputs'/phase/'process-and-policy-journals.tar.gz','w:gz') as archive:
        for f in sorted(out.rglob('*')):
            if f.is_file() and (f.suffix in {'.log','.jsonl'}): archive.add(f,arcname=str(f.relative_to(out)))
with tarfile.open(dest/'fresh-response-coupling.tar.gz','w:gz') as archive:
    archive.add(source/'coupling',arcname='coupling')
hashes={str(p.relative_to(dest)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.rglob('*') if p.is_file()}
(dest/'archive-sha256.json').write_text(json.dumps(hashes,indent=2)+'\n')
print(json.dumps({'archive':str(dest),'files':len(hashes),'bytes':sum(p.stat().st_size for p in dest.rglob('*') if p.is_file())}))
