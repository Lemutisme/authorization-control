"""Model-free exact retained-policy reproduction followed by schema controls."""
import argparse,contextlib,copy,gzip,hashlib,io,json,os,socket,subprocess,sys
from pathlib import Path
sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE']]
def blocked(*a,**k):raise AssertionError('Network forbidden in diagnostic')
socket.create_connection=blocked;socket.socket.connect=blocked
from secagent import tool as progent
from secagent import policy_analysis as pa
from jsonschema import validate
import z3

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,default=str).encode()).hexdigest()
def checked(policy,call):
 progent.security_policy=copy.deepcopy(policy)
 try:progent.check_tool_call(call['function'],copy.deepcopy(call['args']));return {'allowed':True}
 except Exception as exc:return {'allowed':False,'error':str(exc)}
def schema_checks(policy,call):
 out={}
 for name,schema in policy[call['function']][0][2].items():
  if name not in call['args']:continue
  try:validate(call['args'][name],schema);out[name]={'valid':True}
  except Exception as e:out[name]={'valid':False,'error':str(e)}
 return out

def pair(old,new,call):
 log=io.StringIO()
 with contextlib.redirect_stderr(log):subset=progent.security_policy_subset_check(copy.deepcopy(old),copy.deepcopy(new))
 return {'subset_result':subset,'before':checked(old,call),'after':checked(new,call),
         'jsonschema_before':schema_checks(old,call),'jsonschema_after':schema_checks(new,call),'subset_trace':log.getvalue()}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--episode',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--exact-only',action='store_true');a=ap.parse_args()
 raw=json.loads(gzip.decompress(a.episode.read_bytes()));r=raw['result'];old=r['steps'][0]['policy_before'];new=r['steps'][0]['policy_after'];call=r['steps'][0]['decision']['operation']
 progent.api_request=blocked;progent.init_user_query=raw['prompt']
 exact=pair(old,new,call)
 assert exact['subset_result'] is True and exact['before']['allowed'] is False and exact['after']['allowed'] is True
 base=lambda p:{k:[q for q in rows if q[0]<100] for k,rows in p.items() if any(q[0]<100 for q in rows)}
 invariants={'base_unchanged':base(old)==base(new),'same_call':call==r['steps'][1]['decision']['operation'],
             'state_before_each_submission_equal':r['steps'][0]['state_before_sha256']==r['steps'][1]['state_before_sha256'],
             'checker_input_hash_matches_record':digest(old)==r['steps'][0]['subset_checks'][0]['before_sha256'] and digest(new)==r['steps'][0]['subset_checks'][0]['candidate_sha256'],
             'single_generated_allow_rule_per_tool':all(len([q for q in rows if q[0]==100])<=1 and all(q[1]==0 and q[3]==0 for q in rows) for p in [old,new] for rows in p.values())}
 assert all(invariants.values())
 result={'scope':'One completed case record, not main-panel aggregate','episode':str(a.episode),'episode_sha256':sha(a.episode),'progent_commit':subprocess.check_output(['git','-C',os.environ['PROGENT_SOURCE'],'rev-parse','HEAD'],text=True).strip(),'progent_worktree_status':subprocess.check_output(['git','-C',os.environ['PROGENT_SOURCE'],'status','--short'],text=True).strip(),'sources':{name:sha(Path(os.environ['PROGENT_SOURCE'])/'secagent'/name) for name in ['tool.py','policy_analysis.py']},'exact_pair':exact,'invariants':invariants,'before_policy':old,'after_policy':new,'call':call,'model_calls':0,'network_calls':0}
 if not a.exact_only:
  controls=[]
  for keyword in ['const','enum']:
   for typed in [False,True]:
    for kind in ['recipient','amount']:
     oldvalue='US122000000121212121212' if kind=='recipient' else 1195.29
     newvalue='US133000000121212121212' if kind=='recipient' else 0.01
     typ='string' if kind=='recipient' else 'number'
     shape=lambda v:{**({'type':typ} if typed else {}),keyword:v if keyword=='const' else [v]}
     # Single-argument, single-rule constants: clean const-vs-enum comparison.
     before={'probe':[(100,0,{kind:shape(oldvalue)},0)]}
     after={'probe':[(100,0,{kind:shape(newvalue)},0)]}
     c={'function':'probe','args':{kind:newvalue}}
     controls.append({'keyword':keyword,'explicit_type':typed,'argument':kind,**pair(before,after,c)})
  # Preserve entire exact pair, only replace const by singleton enum or add type.
  pair_controls=[]
  for keyword in ['const','enum']:
   for typed in [False,True]:
    b,n=copy.deepcopy(old),copy.deepcopy(new)
    for policy in [b,n]:
     for name,restriction in policy['send_money'][0][2].items():
      if typed:restriction.setdefault('type','number' if name=='amount' else 'string')
      if keyword=='enum' and 'const' in restriction:restriction['enum']=[restriction.pop('const')]
    pair_controls.append({'keyword':keyword,'explicit_type':typed,**pair(b,n,call)})
  exprs={}
  for typ,var,value in [('string',z3.String('diagnostic_x'),'US122000000121212121212'),('number',z3.Real('diagnostic_n'),1195.29)]:
   for typed in [False,True]:
    schema={**({'type':typ} if typed else {}),'const':value}
    exprs[typ+('_typed' if typed else '_implicit')]=str(z3.simplify(z3.And(pa.build_constraints(var,schema))))
  for control in controls+pair_controls:
   assert control['before']['allowed'] is False and control['after']['allowed'] is True
   assert control['subset_result'] is (control['keyword']=='const')
  assert set(exprs.values())=={'True'}
  result.update(minimal_controls=controls,exact_pair_encoding_controls=pair_controls,const_translation=exprs,controls_asserted=True)
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'exact_subset':exact['subset_result'],'before_allowed':exact['before']['allowed'],'after_allowed':exact['after']['allowed'],'invariants':invariants,'minimal_controls':[{k:c[k] for k in ['keyword','explicit_type','argument','subset_result']} for c in result.get('minimal_controls',[])],'const_translation':result.get('const_translation'),'model_calls':0,'network_calls':0},indent=2))
if __name__=='__main__':main()
