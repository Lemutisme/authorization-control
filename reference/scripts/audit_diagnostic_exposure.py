"""Post-hoc manipulation check of the realized downstream fact intervention."""
import argparse,collections,hashlib,json
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--results',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();data=json.loads(a.results.read_text());assert data['complete'] and len(data['rows'])==54
 rows=[]
 for r in data['rows']:
  stages=r['fact_stage_audit'];assert len(stages)==len(r['guard_calls'])
  later=stages[2:]
  for s in later:
   assert s['mode']==r['background']
   if r['background']=='minimal' or s['stage']=='initial':assert not s['visible_fact_keys']
   else:assert s['visible_fact_keys']==s['snapshot_fact_keys']
  rows.append({'case_id':r['case_id'],'replicate':r['replicate'],'background':r['background'],'message':r['message'],'later_review_calls':len(later),'later_adjudications':sum(s['stage']=='adjudication' for s in later),'later_nonempty_fact_messages':sum(bool(s['visible_fact_keys']) for s in later)})
 groups={}
 for bg in ['minimal','late_facts']:
  rs=[r for r in rows if r['background']==bg]
  groups[bg]={'episodes':len(rs),'later_review_calls':sum(r['later_review_calls'] for r in rs),'later_adjudications':sum(r['later_adjudications'] for r in rs),'nonempty_fact_messages':sum(r['later_nonempty_fact_messages'] for r in rs),'exposed_episodes':sum(r['later_nonempty_fact_messages']>0 for r in rs)}
 report={'kind':'Post-hoc manipulation/exposure check; no selection or score changes','source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'input_sha256':hashlib.sha256(a.results.read_bytes()).hexdigest(),'groups':groups,'rows':rows,'limit':'Identical outcomes across configured modes are not evidence of a generally ineffective fact packet; many suffixes never reach a later adjudication.'}
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(groups,indent=2))
if __name__=='__main__':main()
