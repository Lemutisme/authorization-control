"""Write the complete pre-outcome pilot/main schedule and source hashes."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
MODELS=['luna','haiku','deepseek']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    actor=json.loads((HERE/'correctness/frozen-v1/manifest.json').read_text())['rows']
    updates=json.loads((HERE/'updates/index.json').read_text())['units']
    spontaneous=json.loads((HERE/'correctness/frozen-v1/spontaneous-contexts.json').read_text())['contexts']
    for phase in ['pilot','main']:
        aa=actor if phase=='main' else [next(x for x in actor if x['suite']==s) for s in ['banking','slack','travel','workspace']]
        uu=updates if phase=='main' else [next(x for x in updates if x['panel']==s) for s in ['honest_fault','attack','honest_natural']]
        rows=[]
        for unit in aa:
            for model in MODELS:
                for direction in ['corruption','correction']:
                    for feedback in ['value_stating','value_free']:
                        rows.append({'id':'actor__'+unit['packet_id']+'__'+model+'__'+direction+'__'+feedback,
                                     'kind':'actor','model':model,'packet':unit['path'],'packet_sha256':unit['sha256'],
                                     'direction':direction,'feedback':feedback,'repetition':0,'task':unit['cluster_id']})
        for unit in uu:
            for model in MODELS:
                for repetition in range(2 if phase=='main' else 1):
                    for visible in [False,True]:
                        rows.append({'id':'update__'+unit['unit_id']+'__'+model+'__r'+str(repetition)+'__u'+str(int(visible)),
                                     'kind':'update','model':model,'packet':unit['packet'],'packet_sha256':unit['sha256'],
                                     'visible':visible,'repetition':repetition,'panel':unit['panel'],'task':'banking__'+unit['task_id']})
        if phase=='main':
            for unit in spontaneous:
                for model in MODELS:
                    rows.append({'id':'unforced__'+unit['context_id']+'__'+model,'kind':'unforced','model':model,
                                 'packet':unit['packet_path'],'packet_sha256':sha(Path(unit['packet_path'])),
                                 'direction':'corruption','feedback':'value_free','repetition':0,'task':unit['cluster_id']})
        # Cyclic order balances providers within each arm run and does not inspect outcomes.
        protocol={'version':'three-family-authorization-v1','phase':phase,'models':MODELS,
                  'requested_models':{'luna':'gpt-6-luna','haiku':'claude-haiku-5-5','deepseek':'deepseek/deepseek-v4.1-flash'},
                  'rows':rows,'scheduled':len(rows),'counts':{k:sum(r['kind']==k for r in rows) for k in ['actor','update','unforced']},
                  'primary_unit':'Owner task; argument/fault cases and repeated draws are clustered within owner task.',
                  'sampling':'Haiku/Luna native defaults, no requested thinking; DeepSeek temperature0.7, thinking mode recorded separately.',
                  'stopping':'All fixed rows; no efficacy-based early stop. Pilot excluded. Failed/missing rows stay in denominators.'}
        (HERE/('protocol-'+phase+'.json')).write_text(json.dumps(protocol,indent=2)+'\n')
        print(phase,protocol['scheduled'],protocol['counts'])
if __name__=='__main__':main()
