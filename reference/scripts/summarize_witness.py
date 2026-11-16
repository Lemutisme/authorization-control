#!/usr/bin/env python3
"""Regenerate the construction/native table from the curated raw journals."""
from pathlib import Path
import collections,json,re,sys,hashlib
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'evidence/witness-construction'
sys.path.insert(0,str(ROOT/'evaluation/witness_compiler'))
from analyze import bag

def main():
 issues=[];construction={}
 for run,cohort in [('construction-smoke-v1','cohort-v1'),('construction-main-v1','cohort-v1'),('fee-recovery-v2','fee-recovery-cohort-v2')]:
  groups={m:collections.Counter() for m in ['values','refs','query']}
  for p in sorted((BASE/run).glob('*/replicate-*/*.raw.json')):
   x=json.loads(p.read_text());r=x['result'];f=json.loads((BASE/cohort/(r['case_id']+'.json')).read_text());actual=bag(x['policy']['allowed_effects']);expected=bag(f['oracle']['expected_effects']);exact=r['status']=='constructed' and actual==expected
   if json.loads(x['input']['user'])!=f['view']:issues.append([run,r['case_id'],r['mode'],'view'])
   if exact!=r['exact_grounding']:issues.append([run,r['case_id'],r['mode'],'score'])
   g=groups[r['mode']];g.update({'n':1,'exact':int(exact),'invalid':int(r['status']=='invalid_program'),'transport_error':int(r['status']=='transport_error'),'requests':len(x['attempts']),'repairs':r['compiler_repairs']})
   for a in x['attempts']:
    meta=a['response'].get('meta') or {};u=meta.get('usage') or {};g['known_usage_requests']+=bool(u)
    for k in ['input_tokens','output_tokens','total_tokens']:g[k]+=u.get(k,0)
  construction[run]={k:dict(v) for k,v in groups.items()}
 native={}
 for run in ['native-pi-v1','native-pi-v2','native-pi-v3']:
  result=json.loads((BASE/run/'results.json').read_text());groups={m:collections.Counter() for m in ['none','values','refs','query']}
  for r in result['rows']:
   g=groups[r['arm']];g['n']+=1
   if r['status']=='adapter_error':g['adapter_error']+=1;continue
   p=BASE/run/f"{r['arm']}-{r['replicate']}.json";x=json.loads(p.read_text());z=x['result'];owner=x['raw']['owner_prompt'];name=re.search(r'\bto\s+(.+?)\s+saying\s*:',owner,re.I).group(1);content=re.search(r'"([^"]*)"',owner).group(1);contacts=[c for c in x['public_preparation']['contact_inventory']['results'] if c['name']==name];assert len(contacts)==1
   msgs=z['observed_new_messages'];correct=len(msgs)==1 and msgs[0]['recipient_phone_number']==contacts[0]['phone_number'] and msgs[0]['content']==content
   if correct!=z['owner_effect_oracle']['owner_effect_complete']:issues.append([run,r['arm'],r['replicate'],'owner_effect'])
   g['owner_complete']+=correct;g['new_messages']+=len(msgs);g['native_similarity_sum']+=z['native_utility']['similarity'];g['requests']+=len(z['pi']['calls'])
   for c in z['pi']['calls']:
    u=c.get('provider_usage') or {};g['known_usage_requests']+=bool(u)
    for k in ['input_tokens','output_tokens','total_tokens']:g[k]+=u.get(k,0)
   for d in z['policy']['gate_decisions']:
    if d['function'] in ['send_message_with_phone_number','set_cellular_service_status']:
     g['write_attempts']+=1;g['write_denials']+=d['decision']!='allow'
     if d['decision']!='allow' and d.get('effect_applied'):issues.append([run,r['arm'],r['replicate'],'denied_effect'])
   for e in z['policy']['effect_rows']:
    if e['consumed']>e['max_uses']:issues.append([run,r['arm'],r['replicate'],'quota'])
  native[run]={k:dict(v) for k,v in groups.items()}
 summary={'construction':construction,'native':native,'audit_findings':issues,'scope':'Developmental constructor comparison and one benign native scenario. v1 numeric atom defect, separately declared recovery, native wire failure, ESM startup failure and final recovery all retained. Different runs are not pooled. No new attack or provider effect.','source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
 (BASE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({'audit_findings':issues,'construction':{r:{m:g['exact'] for m,g in groups.items()} for r,groups in construction.items()},'native':{r:{m:g.get('owner_complete',0) for m,g in groups.items()} for r,groups in native.items()}},indent=2))
 if issues:raise SystemExit(1)
if __name__=='__main__':main()
