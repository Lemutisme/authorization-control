"""Run the fixed experiment schedules with user-supplied model credentials."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from .paths import ROOT,resolve,workspace

def environment(output):
    env=dict(os.environ)
    envfile=ROOT/'.env'
    if envfile.exists():
        for line in envfile.read_text().splitlines():
            line=line.strip()
            if not line or line.startswith('#'):continue
            key,separator,value=line.partition('=')
            if not separator or not key.replace('_','').isalnum():raise ValueError('Invalid .env assignment')
            env.setdefault(key,value.strip().strip('\"\x27'))
    env.update(AC_WORKSPACE=str(workspace()),AC_PYTHON=sys.executable,PYTHONHASHSEED='20261106',
               CUDA_VISIBLE_DEVICES='',PYTHONDONTWRITEBYTECODE='1',AROS_ARTIFACTS=str(output),
               PYTHONPATH=str(ROOT)+os.pathsep+env.get('PYTHONPATH',''),
               BASELINE_VENDOR=resolve('dependencies'),PROGENT_SOURCE=resolve('progent'))
    if env.get('OPENAI_BASE_URL'):env.setdefault('PGA_API_BASE_URL',env['OPENAI_BASE_URL'])
    if env.get('OPENAI_API_KEY'):env.setdefault('PGA_API_KEY',env['OPENAI_API_KEY'])
    if env.get('CANOPY_API_KEY'):env.setdefault('canopy_wave_key',env['CANOPY_API_KEY'])
    env.setdefault('PGA_MODEL','gpt-6-luna')
    return env

def recipes(study):
    rows=json.loads((ROOT/'experiments/catalog.json').read_text())['runs']
    return [r for r in rows if study=='all' or r['study']==study]

def command(row,output):
    result=[resolve(s)if s.startswith('repo://')else s for s in row['command']]
    for flag,value in [('--out',str(output)),('--coupling-root',str(output.parent/'coupling'))]:
        if flag in result:result[result.index(flag)+1]=value
    return result

def launch(study,output,plan=False):
    from .integrity import verify
    verify()
    from .prepare import prepare
    prepare();output=Path(output).resolve();rows=recipes(study)
    if not rows:raise ValueError('Unknown study: '+study)
    plans=[]
    for row in rows:
        target=output/row['id'];argv=command(row,target)
        entry=next((Path(p)for p in argv if p.endswith('.py')),None)
        if entry is None or not entry.is_file():raise FileNotFoundError('Missing experiment entry point: '+str(entry))
        plans.append({'id':row['id'],'study':row['study'],'argv':argv,'model_calls':row['model_calls']})
    if plan:
        for row in plans:print(row['study']+': '+shlex.join(row['argv']))
        return plans
    if output.exists():raise ValueError('Choose a new output directory; retained results are never overwritten')
    output.mkdir(parents=True);(output/'plan.json').write_text(json.dumps(plans,indent=2)+'\n')
    for row in plans:
        target=output/row['id'];target.mkdir()
        with (target/'run.log').open('w') as log:
            result=subprocess.run(row['argv'],cwd=workspace(),env=environment(target),stdout=log,stderr=subprocess.STDOUT)
        (target/'exit.json').write_text(json.dumps({'returncode':result.returncode})+'\n')
        if result.returncode:raise RuntimeError(row['id']+' failed; see '+str(target/'run.log'))
    return plans
