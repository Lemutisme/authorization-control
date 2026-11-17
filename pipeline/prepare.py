"""Prepare experiment inputs and recorded runs in an isolated working directory."""
import gzip
import hashlib
import json
import lzma
import os
import shutil
import importlib.util
import site
import re
from pathlib import Path
from .paths import ROOT, workspace, relocate,resolve

def stream(name):
    with lzma.open(ROOT/'data'/name,'rt',encoding='utf-8') as source:
        for line in source:yield json.loads(line)

def write(path,value):
    path=Path(path)
    if not path.resolve().is_relative_to(workspace()):raise ValueError('Archive path escapes the working directory')
    path.parent.mkdir(parents=True,exist_ok=True)
    text=json.dumps(value,ensure_ascii=False,separators=(',',':'))
    if 'repo://' in text:
        text=re.sub(r'(?<!\\)"(repo://[^"\\]+)"',lambda m:json.dumps(resolve(m[1]),ensure_ascii=False),text)
    data=(text+'\n').encode()
    if path.name.endswith('.json.gz'):
        path.write_bytes(gzip.compress(data,compresslevel=3,mtime=0))
        if isinstance(value,dict) and 'result' in value:path.with_suffix('').write_text(json.dumps(value['result'])+'\n')
    elif path.name.endswith(('.jsonl','.jsonl.gz')):
        data=('\n'.join(json.dumps(relocate(row),ensure_ascii=False)for row in value)+'\n').encode()
        path.write_bytes(gzip.compress(data,compresslevel=3,mtime=0) if path.suffix=='.gz' else data)
    else:path.write_bytes(data)

def prepare(force=False):
    work=workspace();work.mkdir(parents=True,exist_ok=True)
    bind_native(work)
    marker=work/'prepared.json';fingerprint=hashlib.sha256((ROOT/'experiments/SOURCES.json').read_bytes()+(ROOT/'data/paper-studies-index.json').read_bytes()).hexdigest()
    if marker.exists() and not force and json.loads(marker.read_text()).get('fingerprint')==fingerprint:
        index_frozen_prefixes(work)
        return work
    shutil.copytree(ROOT/'experiments',work/'experiments',dirs_exist_ok=True)
    if (ROOT/'inputs').exists():shutil.copytree(ROOT/'inputs',work/'inputs',dirs_exist_ok=True)
    (work/'pipeline').mkdir(exist_ok=True);shutil.copy2(ROOT/'pipeline/paths.mjs',work/'pipeline/paths.mjs')
    for record in stream('experiment-inputs.jsonl.xz'):write(work/record['path'],record['data'])
    for record in stream('paper-studies.jsonl.xz'):
        if record['kind']=='command':continue
        write(work/'runs'/record['run']/record['path'],record['data'])
    metadata=ROOT/'data/run-metadata.jsonl.xz'
    if metadata.exists():
        for record in stream(metadata.name):write(work/'runs'/record['run']/record['path'],record['data'])
    for record in stream('fault-injection.jsonl.xz'):
        if record['kind']=='run':
            c=record['condition'];write(work/'runs/authorship-x1-main-v1'/c['unit_id']/(c['condition_id']+'.json.gz'),record['raw'])
    for record in stream('matched-inputs.jsonl.xz'):
        if record['kind']=='run':write(work/'runs/matched-inputs'/record['unit_id']/f"repetition-{record['repetition']}"/(record['arm']+'.json.gz'),record['raw'])
    mapping=json.loads((ROOT/'data/model-file-map.json').read_text())
    for record in stream('model-continuations.jsonl.xz'):
        if record['kind']=='raw':
            for name in mapping['raw'].get(record['record_id'],[]):write(work/name,record['raw'])
        elif record['kind']=='packet':
            for name in mapping['packet'].get(record['record_id'],[]):write(work/name,record['packet'])
    node_modules=ROOT/'node_modules'
    if node_modules.exists():
        for package in (work/'experiments').rglob('package.json'):
            link=package.parent/'node_modules'
            if not link.exists():link.symlink_to(node_modules,target_is_directory=True)
        if not (work/'node_modules').exists():(work/'node_modules').symlink_to(node_modules,target_is_directory=True)
    rebase_checksums(work)
    index_frozen_prefixes(work)
    marker.write_text(json.dumps({'fingerprint':fingerprint,'workspace':str(work)},indent=2)+'\n')
    return work

def index_frozen_prefixes(work):
    for path in (work/'runs/authorship-x1-prefix-main-v1').glob('*/prefix.json.gz'):
        raw=json.loads(gzip.decompress(path.read_bytes()));requests={}
        cache=path.parent/'actor-cache'
        for call in raw['result']['pi']['calls']:
            wire=call.get('request_sha256');coupling=call.get('coupling') or {};key=coupling.get('request_sha256')
            if wire and key and (cache/(key+'.json')).exists():
                requests[wire]={'cache_key':key,'response_sha256':coupling['response_sha256']}
        (cache/'frozen-index.json').write_text(json.dumps({'version':1,'scope':'Recorded source-prefix responses; not fresh model samples.','requests':requests},indent=2)+'\n')

def bind_native(work):
    native=work/'native';(native/'sources').mkdir(parents=True,exist_ok=True)
    pairs=[(native/'vendor',Path(site.getsitepackages()[0]))]
    try:pairs.append((native/'sources/progent',Path(resolve('progent'))))
    except RuntimeError:pass
    for link,target in pairs:
        if link.is_symlink() and link.resolve()!=target.resolve():link.unlink()
        if not link.exists():link.symlink_to(target,target_is_directory=True)

def rebase_checksums(work):
    """Rebind file-integrity pins after path relocation, retaining an audit map."""
    source=json.loads((ROOT/'experiments/SOURCES.json').read_text())
    originals={str(work/r['path']):r['original_sha256']for r in source['files']}
    for r in stream('experiment-inputs.jsonl.xz'):originals[str(work/r['path'])]=r['original_sha256']
    aliases={old:{name}for name,old in originals.items()}
    # Multiple copies of identical sources are valid only while their bytes agree.
    for name,old in originals.items():aliases.setdefault(old,set()).add(name)
    paths=[p for p in (work/'experiments').rglob('*') if p.is_file() and p.suffix in {'.json','.py'} and 'node_modules' not in p.parts]
    paths += [p for p in (work/'inputs').rglob('*.json')] if (work/'inputs').exists() else []
    changed=0
    for iteration in range(12):
        current={name:hashlib.sha256(Path(name).read_bytes()).hexdigest()for name in originals if Path(name).exists()}
        replacements={old:next(iter({current[n]for n in names if n in current}))for old,names in aliases.items()
                      if len({current[n]for n in names if n in current})==1}
        count=0
        for path in paths:
            text=path.read_text()
            import re
            updated=re.sub(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',lambda m:replacements.get(m[0],m[0]),text)
            if updated!=text:path.write_text(updated);count+=1
        for name,digest in current.items():aliases.setdefault(digest,set()).add(name)
        changed+=count
        if not count:break
    report={'files_changed_for_portability':changed,'passes':iteration+1,'files':[
        {'path':str(Path(name).relative_to(work)),'original_sha256':old,'workspace_sha256':hashlib.sha256(Path(name).read_bytes()).hexdigest()}
        for name,old in originals.items()if Path(name).exists()]}
    (work/'relocation.json').write_text(json.dumps(report,indent=2)+'\n')
