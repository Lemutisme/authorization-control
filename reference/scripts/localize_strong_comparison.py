"""Locate the first actor-context fork in all paired utility discordances."""
import argparse,collections,gzip,hashlib,json,random
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sequence(ep):return [(c['coupling']['request_sha256'],c['coupling']['response_sha256']) for c in ep['pi']['calls']]
def main():
    p=argparse.ArgumentParser();p.add_argument('--job',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();data=json.loads((a.job/'results.json').read_text());assert data['complete'];rows=[];bytask=collections.defaultdict(list)
    for pair in data['rows']:
        left,right=pair['arms']['pga_minimal'],pair['arms']['progent'];gain=int(left['native_utility'])-int(right['native_utility'])
        if pair['condition']=='attack':bytask[pair['task_id']].append(gain)
        if not gain:continue
        sa,sb=sequence(left),sequence(right);first=next((i for i,(x,y) in enumerate(zip(sa,sb)) if x!=y),min(len(sa),len(sb)) if len(sa)!=len(sb) else None)
        common=[];statuses={};rawhash={};initials=[]
        if first is not None and first>0:
            saved=json.loads((a.job/pair['case_id']/'actor-cache'/(sa[first-1][0]+'.json')).read_text());common=[c for c in saved['message']['content'] if c['type']=='toolCall']
        for arm in ['pga_minimal','progent']:
            rp=a.job/pair['case_id']/(arm+'.json.gz');raw=json.loads(gzip.decompress(rp.read_bytes()));rawhash[arm]=sha(rp);initials.append(raw['initial'])
            ends={e['call_id']:e['is_error'] for e in raw['pi_tool_events'] if e['type']=='tool_execution_end'}
            statuses[arm]=[ends.get(c['id']) for c in common]
        if first is None:kind='no_actor_hash_difference'
        elif len(common)!=1:kind='no_single_previous_common_tool'
        elif any(s[0] is None for s in statuses.values()):kind='missing_tool_completion'
        elif statuses['pga_minimal']!=statuses['progent']:kind='different_tool_error_status'
        elif statuses['pga_minimal']==[True]:kind='both_tool_errors_before_context_fork'
        else:kind='both_tool_successes_before_context_fork'
        rows.append({'case_id':pair['case_id'],'condition':pair['condition'],'pga_utility_gain':gain,'same_initial':initials[0]==initials[1],'first_actor_difference':first,'previous_shared_tool_names':[c['name'] for c in common],'tool_error_status':statuses,'localization':kind,'raw_sha256':rawhash})
    values=list(bytask.values());rng=random.Random(20261109);draws=[]
    for _ in range(10000):
        samples=[values[rng.randrange(len(values))] for _ in values];draws.append(sum(map(sum,samples))/sum(map(len,samples)))
    draws.sort();result={'kind':'Post-hoc localization of all observed PGA/Progent utility discordances','source_sha256':sha(Path(__file__)),'results_sha256':sha(a.job/'results.json'),'rows':rows,'counts':dict(collections.Counter(r['localization'] for r in rows)),'attack_task_deltas':{k:{'n':len(v),'net_utility_gain':sum(v)} for k,v in sorted(bytask.items())},'descriptive_task_bootstrap':{'tasks':len(values),'resamples':len(draws),'mean':sum(map(sum,values))/sum(map(len,values)),'percentile_95':[draws[249],draws[9749]],'scope':'Post-hoc resampling of the16observed owner-task clusters. Not a prespecified population test or holdout guarantee.'},'limits':['Cases selected by utility disagreement; overlapping attack variants are not independent task samples.','A first context fork locates differing tool-facing status, not the sole cause of the final result.','Both-error cases do not establish identical authorization verdicts or justify a message-only causal claim.','No change to native labels, main denominator, policy or model responses.']}
    a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['rows','attack_task_deltas']},indent=2))
if __name__=='__main__':main()
