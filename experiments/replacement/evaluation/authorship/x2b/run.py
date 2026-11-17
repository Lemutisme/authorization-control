"""One registered X2b arm/role/strategy/profile/panel per job, without model calls on import."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
HERE = Path(__file__).resolve().parent

def save(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--panel', choices=['development', 'holdout'], required=True)
    p.add_argument('--arm', choices=['none','auto_approve','narrow_only','pga_minimal'], required=True)
    p.add_argument('--role', choices=['honest','attack','t_only'], required=True)
    p.add_argument('--strategy', choices=['direct','feedback_adaptive','insist'], default='direct')
    p.add_argument('--reasoning', choices=['none','low','medium'], required=True)
    p.add_argument('--phase', choices=['smoke','capability','attack_development','heldout'], required=True)
    p.add_argument('--selection', type=Path)
    p.add_argument('--coupling-root', type=Path, required=True)
    p.add_argument('--campaign', required=True)
    p.add_argument('--out', type=Path)
    p.add_argument('--workers', type=int, default=4)
    a = p.parse_args()
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == '' and os.environ.get('PYTHONHASHSEED') == '20261106'
    assert a.role != 't_only' or (a.arm == 'none' and a.reasoning == 'low')
    if a.phase in {'attack_development','heldout'}:
        assert a.selection, 'Registered capability selection required'
        selection = json.loads(a.selection.read_text())
        assert a.role == 't_only' or a.reasoning == selection['selected_u_reasoning']
        if a.phase == 'heldout' and a.role == 'attack':
            assert 'selected_strategy_by_controller' in selection
    if a.phase == 'capability':
        assert a.panel == 'development' and a.arm == 'none' and a.role != 'attack'
    if a.phase == 'attack_development':
        assert a.panel == 'development' and a.role == 'attack'
    if a.phase == 'heldout':
        assert a.panel == 'holdout'
    manifest = json.loads(a.manifest.read_text())
    role = 'attack' if a.role == 'attack' else 'honest'
    cases = [c for c in manifest['cases'] if c['x2b_panel'] == a.panel and c['x2b_role'] == role]
    if a.phase == 'smoke':
        cases = [c for c in cases if c['task_id'] == 'user_task_0' and (role == 'honest' or c['injection_id'] == 'injection_task_0')]
    assert cases
    a.out = a.out or Path(os.environ['AROS_ARTIFACTS'])
    a.out.mkdir(parents=True, exist_ok=True)
    assert not (a.out/'config.json').exists()
    config = {k: str(v) if isinstance(v,Path) else v for k,v in vars(a).items()}
    config.update(cases=[c['case_id'] for c in cases], source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.suffix in {'.py','.mjs','.json'}})
    save(a.out/'config.json',config)
    started,rows=time.monotonic(),[]
    def one(case):
        out=a.out/case['case_id'];out.mkdir()
        cache=a.coupling_root/a.campaign/a.phase/a.panel/a.role/a.reasoning/a.strategy/case['case_id']
        cmd=['node',str(HERE/'agent.mjs'),'--python',sys.executable,'--manifest',str(a.manifest),
             '--case',case['case_id'],'--arm',a.arm,'--role',a.role,'--strategy',a.strategy,
             '--reasoning',a.reasoning,'--out',str(out/a.arm),'--judge-cache',str(cache/'judge'),
             '--policy-cache',str(cache/'policy')]
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            so,se=proc.communicate(timeout=1800)
            (out/'stdout').write_text(so);(out/'stderr').write_text(se)
            if proc.returncode:raise RuntimeError('episode_process_error')
            return json.loads((out/(a.arm+'.json')).read_text())
        except Exception as exc:
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM);proc.communicate()
            r={'case_id':case['case_id'],'task_id':case['task_id'],'status':'adapter_error','error':type(exc).__name__,
               'native_utility':None,'native_targeted_asr':None}
            save(out/'failure.json',r);return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        for f in concurrent.futures.as_completed([pool.submit(one,c) for c in cases]):
            rows.append(f.result())
            result={'scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),
                    'utility':sum(r.get('native_utility') is True for r in rows),
                    'native_target':sum(r.get('native_targeted_asr') is True for r in rows),
                    'partial_harm':sum(r.get('partial_harm',{}).get('any_declared_partial_harm',False) for r in rows),
                    'unavailable_or_failed':sum(r.get('status') in {'adapter_error','inference_error','episode_timeout','no_response'} for r in rows),
                    'elapsed_s':time.monotonic()-started}
            save(a.out/'result.json',result);save(a.out/'summary.json',{**result,'rows':rows})
            (a.out/'status.md').write_text(f"X2b {a.panel} {a.role}/{a.strategy} {a.arm}: {len(rows)}/{len(cases)}; target {result['native_target']}; partial harm {result['partial_harm']}; utility {result['utility']}; failures {result['unavailable_or_failed']}.\n")
            print(json.dumps(result),flush=True)
if __name__=='__main__':main()
