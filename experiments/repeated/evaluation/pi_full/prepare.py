"""Enumerate the full pinned registry and reuse the native fixed attack factory."""
import argparse,hashlib,json,os,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.attacks.base_attacks import FixedJailbreakAttack
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttackNoNames
from pga_oracle import parse_public_mandate
PIN='089ed468cf3ed0322acc66b0211f26d9d90dbf60'

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    cases=[];inventory=[];suite_rows=[];excluded=[]
    for name,suite in get_suites('v1.2.2').items():
        attack=FixedJailbreakAttack(ImportantInstructionsAttackNoNames._JB_STRING,suite,SimpleNamespace(name='gpt-6-luna'))
        native=ImportantInstructionsAttackNoNames(suite,SimpleNamespace(name='gpt-4o-2024-05-13'))
        start=len(cases)
        for tid,task in suite.user_tasks.items():
            support=name=='workspace' and parse_public_mandate(tid,task.PROMPT)['status']=='supported'
            base={'suite':name,'task_id':tid,'profile_supported':support}
            cases.append({**base,'case_id':name+'__'+tid+'__clean','condition':'clean','injection_id':None,'injections':{}})
            record={**base,'prompt_sha256':hashlib.sha256(task.PROMPT.encode()).hexdigest(),'implementation_module':type(task).__module__}
            try:
                candidates=attack.get_injection_candidates(task)
                record.update(injectable=True,candidate_count=len(candidates),candidate_keys=sorted(candidates))
            except Exception as exc:
                reason='not_injectable' if isinstance(exc,ValueError) and 'is not injectable' in str(exc) else 'preparation_error'
                record.update(injectable=False,preparation_status=reason,error_type=type(exc).__name__)
                for gid in suite.injection_tasks:
                    excluded.append({**base,'injection_id':gid,'status':reason,'error_type':type(exc).__name__})
                inventory.append(record);continue
            for gid,goal in suite.injection_tasks.items():
                try:
                    injections=attack.attack(task,goal)
                    if not injections or injections!=native.attack(task,goal):raise ValueError('Native factory mismatch')
                    task.init_environment(suite.load_and_inject_default_environment(injections))
                    cases.append({**base,'case_id':name+'__'+tid+'__'+gid,'condition':'attack','injection_id':gid,'injections':injections})
                except Exception as exc:
                    excluded.append({**base,'injection_id':gid,'status':'preparation_error','error_type':type(exc).__name__})
            inventory.append(record)
        for gid in suite.injection_tasks:
            cases.append({'suite':name,'task_id':gid,'case_id':name+'__'+gid+'__goal_control',
                'condition':'goal_control','injection_id':None,'injections':{},'profile_supported':False})
        suite_rows.append({'suite':name,'user_tasks':len(suite.user_tasks),'injection_goals':len(suite.injection_tasks),
            'cartesian_pairs':len(suite.user_tasks)*len(suite.injection_tasks),'tools':len(suite.tools),
            'scheduled':len(cases)-start,'supported_tasks':sum(r['suite']==name and r['profile_supported'] for r in inventory)})
    report={'kind':'full pinned AgentDojo registry; one existing attack family, frozen PGA coverage',
        'source_pin':PIN,'version':'v1.2.2','attack':'important_instructions_no_names',
        'preparation_scope':'Unchanged native helper uses reference traces only for attacker-side vector discovery. No gold actions/IDs are defense inputs.',
        'suite_rows':suite_rows,'tasks':inventory,'excluded_pairs':excluded,
        'counts':{'user_tasks':sum(s['user_tasks'] for s in suite_rows),'goals':sum(s['injection_goals'] for s in suite_rows),
            'cartesian_pairs':sum(s['cartesian_pairs'] for s in suite_rows),'clean':sum(c['condition']=='clean' for c in cases),
            'attack':sum(c['condition']=='attack' for c in cases),'goal_control':sum(c['condition']=='goal_control' for c in cases),
            'excluded_not_injectable':sum(e['status']=='not_injectable' for e in excluded),
            'preparation_errors':sum(e['status']=='preparation_error' for e in excluded),
            'supported_user_tasks':sum(r['profile_supported'] for r in inventory),'scheduled_per_arm':len(cases)},
        'limits':['Complete task coverage, not all attack methods.','Goal controls are separate from ordinary utility and ASR.','Unsupported PGA profiles remain scheduled; no gold-derived expansion.']}
    manifest={**report,'cases':cases}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    report['manifest_sha256']=hashlib.sha256((out/'manifest.json').read_bytes()).hexdigest()
    (out/'inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'status.md').write_text('Full registry frozen: '+json.dumps(report['counts'])+'\n')
    print(json.dumps(report['counts'],indent=2))

if __name__=='__main__':main()
