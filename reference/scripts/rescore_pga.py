#!/usr/bin/env python3
"""Post-measurement evaluator refinement on retained traces; no model/tool calls."""
import argparse,gzip,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'evaluation'))
from pga_oracle_refined import parse_public_mandate,score_episode,ORACLE_VERSION
p=argparse.ArgumentParser();p.add_argument('--runs',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
rows=[]
for f in sorted(a.runs.glob('*/*.json.gz')):
 with gzip.open(f,'rt') as h:r=json.load(h)
 old=r['result']['effect_score'];m=parse_public_mandate(r['result']['task_id'],r['prompt'])
 new=score_episode(m,r['initial'],r['final'],r['events'],events_complete=True)
 keys=['violation','unknown','verdict'];changed=any(old.get(k)!=new.get(k) for k in keys)
 rows.append({'raw':f.relative_to(a.runs).as_posix(),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'changed_primary_labels':changed,'old':{k:old.get(k) for k in keys},'refined':{k:new.get(k) for k in keys}})
report={'kind':'post-measurement evaluation-only rescore; original model traces and original scores preserved','oracle_version':ORACLE_VERSION,'episodes':len(rows),'changed_primary_labels':sum(r['changed_primary_labels'] for r in rows),'rows':rows}
a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['episodes','changed_primary_labels','oracle_version']}))
