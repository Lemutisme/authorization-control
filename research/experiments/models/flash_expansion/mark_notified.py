"""Persist callback delivery receipts; no experiment data is changed."""
import json,re,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    keys=sys.argv[1:]
    if not keys or any(not re.fullmatch(r'[a-z0-9-]+',k) for k in keys):raise ValueError('Invalid callback milestone')
    path=HERE/'callback/notified.json';path.parent.mkdir(exist_ok=True)
    try:data=json.loads(path.read_text())
    except (OSError,ValueError):data={'milestones':[],'deliveries':[]}
    data['milestones']=sorted(set(data['milestones'])|set(keys));data['deliveries'].append({'keys':keys,'epoch':time.time()})
    path.write_text(json.dumps(data,indent=2)+'\n');print(json.dumps({'marked':keys}))
if __name__=='__main__':main()
