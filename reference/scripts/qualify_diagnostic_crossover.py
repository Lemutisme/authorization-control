"""Audit all no-network prefix replays and reject a corrupted replay identity."""
import argparse,collections,copy,gzip,hashlib,json,subprocess,tempfile
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--qualification',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--agent',type=Path,required=True);p.add_argument('--python',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 data=json.loads((a.qualification/'results.json').read_text());m=json.loads(a.manifest.read_text());assert data['complete'] and len(data['rows'])==18
 checks=[];groups=collections.defaultdict(list)
 for r in data['rows']:
  groups[r['case_id'],r['background']].append(r)
  assert r['status']=='model_round_limit' and r['qualify'] and r['boundary']['judgment_unchanged']
  for c in r['pi']['calls']+r['guard_calls']:assert c.get('historical_replay') is True and c['actual_network_call'] is False
  assert len(r['guard_decisions'])==1 and r['guard_decisions'][0]['decision']=='deny'
  assert len(r['guard_calls'])==r['boundary']['prefix_judge_calls']==2
  checks.append({'case_id':r['case_id'],'background':r['background'],'message':r['message'],'passed':True})
 for key,rows in groups.items():
  assert len(rows)==3 and len({r['boundary']['denial_sha256'] for r in rows})==1 and len({r['boundary']['native_state_sha256'] for r in rows})==1
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='crossover-negative-',dir=a.out.parent) as work:
  work=Path(work);c=m['cases'][0];envelope=json.loads((a.manifest.parent/c['path']).read_text());envelope['backgrounds']['minimal']['actor_prefix'][0]['wire_request_sha256']='0'*64
  source=work/c['path'];source.write_text(json.dumps(envelope));modified=copy.deepcopy(m);modified['cases']=[{**c,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]
  (work/m['native_manifest']).write_bytes((a.manifest.parent/m['native_manifest']).read_bytes());(work/'manifest.json').write_text(json.dumps(modified))
  command=['node',str(a.agent),'--manifest',str(work/'manifest.json'),'--case',c['case_id'],'--background','minimal','--message','minimal_reason','--python',a.python,'--out',str(work/'episode'),'--actor-cache',str(work/'actor-cache'),'--judge-cache',str(work/'judge-cache'),'--qualify','true']
  result=subprocess.run(command,capture_output=True,text=True,timeout=60)
  assert result.returncode!=0 and 'Incomplete historical prefix' in result.stderr and not (work/'episode.json').exists()
  checks.append({'name':'corrupted_actor_request_identity_rejected_before_fresh_inference','passed':True})
 result={'kind':'No-network replay qualification, not task efficacy','passed':len(checks),'n':len(checks),'checks':checks,'historical_actor_draws':sum(len(r['pi']['calls']) for r in data['rows']),'historical_reviewer_draws':sum(len(r['guard_calls']) for r in data['rows']),'new_model_requests':0,'qualification_results_sha256':hashlib.sha256((a.qualification/'results.json').read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_event_equality':'All fields except elapsed_s, plus exact native world, proposal, decision and review request checks.'}
 a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'n':result['n'],'new_model_requests':0}))
if __name__=='__main__':main()
