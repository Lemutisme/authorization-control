"""Launch the registered quota-scoped DeepSeek diagnostic after its pilot."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    runtime=HERE/'runtimes/focused-v1'
    if runtime.exists():raise ValueError('Fresh focused runtime required')
    runtime.mkdir(parents=True)
    sources=[HERE/n for n in ['actor_trial.py','update_trial.py','campaign.py','launch_focused.py','analyze.py','test_analysis.py']]
    sources += [p for p in (HERE/'provider').glob('*') if p.suffix in {'.py','.mjs'}]
    sources += [HERE/'correctness/native.py']
    for src in sources:
        dst=runtime/src.relative_to(HERE);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
    (runtime/'source-sha256.json').write_text(json.dumps({str(p.relative_to(runtime)):hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.rglob('*') if p.is_file()},indent=2)+'\n')
    cmd=['python3','-B',AROS,'run','start','--name','focused-deepseek-all-v1','--main','--after','pilot-deepseek-all-v3',
         '--question',PREFIX+'haiku-crossmodel.md','--predict',PREFIX+'deepseek-focused.md','--memory','6']
    files=list(p for p in runtime.rglob('*') if p.is_file())+[HERE/'protocol-focused.json',HERE/'focused-prediction.md']
    protocol=json.loads((HERE/'protocol-focused.json').read_text())
    files += [Path(r['packet']) for r in protocol['rows']]
    for path in sorted(set(files)):cmd+=['--input',str(path)]
    for path in ['/artifact-source/398180b38ed7/venv',
                 '/artifact-source/9c9de9c2a04c/frozen-x1-branch-v1',
                 '/artifact-source/3d9fa19e91e5/vendor',
                 '/artifact-source/c4751a2fc0fe/progent',
                 '/artifact-source/7defb8251014/channels.py',
                 '/artifact-source/ec5d02833076/node_modules']:cmd+=['--reference',path]
    cmd+=['--','python3','-B',str(runtime/'campaign.py'),'--protocol',str(HERE/'protocol-focused.json'),
          '--model','deepseek','--kind','all','--workers','1','--out',str(HERE/'outputs/focused-deepseek-all-v1')]
    result=subprocess.run(cmd,cwd=HERE,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1',
                          'HAIKU_STUDY_RATE_DIR':str(HERE/'transport-state')},text=True,capture_output=True)
    (HERE/'launch-focused-v1.json').write_text(json.dumps({'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr},indent=2)+'\n')
    print(json.dumps({'returncode':result.returncode,'stdout':result.stdout[:300],'stderr':result.stderr[:300]}))
    raise SystemExit(result.returncode)
if __name__=='__main__':main()
