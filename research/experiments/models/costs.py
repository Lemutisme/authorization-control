"""Observed per-run CPU/wall/API usage; no guessed provider price or GPU use."""
import csv,gzip,json
from datetime import datetime
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    rows=[]
    for folder in sorted((HERE/'outputs').iterdir()):
        if not folder.is_dir():continue
        jp=HERE/'research/jobs'/folder.name/'job.json'
        if not jp.exists():continue
        job=json.loads(jp.read_text());row={'run':folder.name,'finished':job.get('finished'),
            'cpu_h':(job.get('compute') or {}).get('cpu_h'),'local_gpu_h':(job.get('compute') or {}).get('gpu_h'),
            'provider_gpu_h':None,'provider_invoice_cost':None,'raw_trials':0,'requests_recorded':0,
            'input_tokens':0,'output_tokens':0,'cache_read_tokens':0,'cache_write_tokens':0,'missing_usage_requests':0}
        if job.get('started') and job.get('finished'):row['run_wall_s']=(datetime.fromisoformat(job['finished'])-datetime.fromisoformat(job['started'])).total_seconds()
        else:row['run_wall_s']=None
        for p in (folder/'raw').glob('*.json.gz'):
            raw=json.loads(gzip.decompress(p.read_bytes()));row['raw_trials']+=1
            for request in raw.get('requests',[]):
                row['requests_recorded']+=request.get('network_requests',1);usage=request.get('usage')
                if not usage:row['missing_usage_requests']+=1;continue
                row['input_tokens']+=usage.get('input_tokens',usage.get('prompt_tokens',0))
                row['output_tokens']+=usage.get('output_tokens',usage.get('completion_tokens',0))
                row['cache_read_tokens']+=usage.get('cache_read_input_tokens',0)
                row['cache_write_tokens']+=usage.get('cache_creation_input_tokens',0)
        rows.append(row)
    out=HERE/'costs';out.mkdir(exist_ok=True)
    (out/'observed.json').write_text(json.dumps({'rows':rows,'scope':'Completed raw-record request usage; failed process rows without raw traces can have unknown request cost. Input-token conventions differ by provider; no cross-model token equivalence or invoice estimate.'},indent=2)+'\n')
    if rows:
        with (out/'observed.csv').open('w') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print(json.dumps({'runs':len(rows),'completed_runs':sum(bool(r['finished']) for r in rows),'recorded_requests':sum(r['requests_recorded'] for r in rows)}))
if __name__=='__main__':main()
