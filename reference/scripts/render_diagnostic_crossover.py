"""Render finite paired contrasts from the audited crossover, without inference."""
import argparse,hashlib,json
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);a=p.parse_args();summary=json.loads((a.evidence/'summary.json').read_text());rows=json.loads((a.evidence/'case-details.json').read_text());lookup={(r['case_id'],r['replicate'],r['background'],r['message']):r for r in rows}
 contrasts=[];backgrounds=[]
 for cid in sorted({r['case_id'] for r in rows}):
  for bg in ['minimal','late_facts']:
   for candidate,reference in [('late_reason','minimal_reason'),('status_only','minimal_reason'),('status_only','late_reason')]:
    pairs=[(lookup[cid,r,bg,candidate],lookup[cid,r,bg,reference]) for r in range(3)]
    contrasts.append({'case_id':cid,'background':bg,'candidate_message':candidate,'reference_message':reference,'pairs':3,'utility_gains':sum(x['native_utility'] and not y['native_utility'] for x,y in pairs),'utility_losses':sum(not x['native_utility'] and y['native_utility'] for x,y in pairs),'effect_sequence_differences':sum(x['effect_operations']!=y['effect_operations'] for x,y in pairs)})
  for msg in ['minimal_reason','late_reason','status_only']:
   pairs=[(lookup[cid,r,'minimal',msg],lookup[cid,r,'late_facts',msg]) for r in range(3)]
   backgrounds.append({'case_id':cid,'message':msg,'pairs':3,'utility_discordances':sum(x['native_utility']!=y['native_utility'] for x,y in pairs),'first_request_discordances':sum(x['first_fresh_request']!=y['first_fresh_request'] for x,y in pairs),'effect_sequence_discordances':sum(x['effect_operations']!=y['effect_operations'] for x,y in pairs)})
 result={'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'message_contrasts':contrasts,'background_contrasts':backgrounds,'scope':'Descriptive within-case contrasts. Background pairs share first actor samples by design; repetitions and backgrounds are not independent task evidence.'}
 (a.evidence/'contrasts.json').write_text(json.dumps(result,indent=2)+'\n')
 lines=['# Fixed-denial crossover: audited finite results','','Each cell is native utility out of three fresh suffix replicate namespaces. Both fixed authorizer backgrounds have the same counts; see the JSON/CSV for each individual episode. The cases were selected using historical outcomes.','','| Case | Archived minimal reason | Archived late-facts reason | Neutral status |','|---|---:|---:|---:|']
 for cid in sorted({r['case_id'] for r in rows}):
  vals=[]
  for msg in ['minimal_reason','late_reason','status_only']:
   a0=next(c for c in summary['cells'] if (c['case_id'],c['background'],c['message'])==(cid,'minimal',msg));a1=next(c for c in summary['cells'] if (c['case_id'],c['background'],c['message'])==(cid,'late_facts',msg));assert a0['utility']==a1['utility'];vals.append(str(a0['utility'])+'/3')
  lines.append('| '+cid+' | '+' | '.join(vals)+' |')
 lines+=['',f"Completed {summary['episodes']} episodes; audit findings {len(summary['audit_findings'])}; targeted native ASR positives {sum(c['asr'] for c in summary['cells'])}. Elapsed {summary['elapsed_s']:.2f}s.",'','Fresh cost: `'+json.dumps(summary['cost'],sort_keys=True)+'`. Historical actor/reviewer replays: '+str(summary['historical_actor_calls'])+'/'+str(summary['historical_judge_calls'])+'. These are not newly issued inference requests.','','No prevalence, holdout, comparative-defense or universal-safe-completion claim follows. Donor explanations are experimental variables, not an implemented verified-feedback method.']
 (a.evidence/'results.md').write_text('\n'.join(lines)+'\n');print('Rendered finite crossover contrasts and table.')
if __name__=='__main__':main()
