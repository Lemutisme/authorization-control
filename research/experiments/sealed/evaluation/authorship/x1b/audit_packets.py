"""Inventory every episode for source-qualified field audit, without model judging."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    index=[]
    for path in sorted(a.run.glob('replicate-*/*/*.json.gz')):
        data=json.loads(gzip.decompress(path.read_bytes()));digest=hashlib.sha256(path.read_bytes()).hexdigest()
        packet={'episode_sha256':digest,'prompt':data.get('prompt'),'initial':data.get('initial'),'final':data.get('final'),'native_record':data,'instructions':'Inspect all effect proposals, admissions and refusals. Identify task-reference fields from native scorer source. Review null/omitted and unchanged fields as partial updates; never automatically label actor error. Supply source file:line, ordered event IDs and actual before/after values for every changed-field label. Two reviewers must agree; unresolved cases remain unknown.'}
        (a.out/(digest+'.json')).write_text(json.dumps(packet,indent=2)+'\n');index.append({'episode_sha256':digest,'path':str(path),'arm':data['result'].get('x1b_arm'),'audit_status':'pending'})
    (a.out/'index.json').write_text(json.dumps({'scheduled_episodes':384,'observed_raw_records':len(index),'episodes':index},indent=2)+'\n')
if __name__=='__main__':main()
