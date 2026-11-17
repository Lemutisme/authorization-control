"""Exercise a complete fresh fault fork with different credentials and no model calls."""
import gzip
import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pipeline.paths import ROOT,workspace
from pipeline.launch import environment
from pipeline.prepare import prepare

prepare();out=Path(tempfile.mkdtemp(prefix='prefix-fixture-',dir=ROOT/'results'))
env=environment(out)
env.update(PGA_API_BASE_URL='https://prefix-fixture.invalid/v1',PGA_API_KEY='new-fixture-principal',
           NODE_OPTIONS='--import '+str(ROOT/'test/frozen-prefix-fetch.mjs'),AC_FIXTURE_JOURNAL=str(out/'fixture.jsonl'))
argv=[sys.executable,'-B',str(workspace()/'experiments/faults/evaluation/authorship/x1/campaign.py'),
      '--cohort',str(workspace()/'experiments/faults/evaluation/authorship/x1/cohort.json'),
      '--prefix',str(workspace()/'runs/authorship-x1-prefix-main-v1'),
      '--branches',str(workspace()/'runs/authorship-x1-prepare-v2/branches/manifest.json'),
      '--phase','smoke','--out',str(out)]
with (out/'run.log').open('w') as stream:
    result=subprocess.run(argv,env=env,cwd=workspace(),stdout=stream,stderr=subprocess.STDOUT,timeout=180)
assert result.returncode==0,(out/'run.log').read_text()
summary=json.loads((out/'result.json').read_text());assert summary['scheduled']==summary['known']==3,summary
replays=0
for path in out.glob('*/*.json.gz'):
    if path.name=='none.json.gz':continue
    raw=json.loads(gzip.decompress(path.read_bytes()))
    assert raw['result']['x1_anchor']
    replays+=sum(call['coupling'].get('frozen_prefix_replay',False) for call in raw['result']['pi']['calls'])
assert replays>=6,replays
print(json.dumps({'episodes':3,'prefix_replays':replays,'live_model_calls':0,'out':str(out)}))
