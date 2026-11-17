"""Two fresh blinded annotation draws per unique packet; no actor/control calls."""
import argparse,concurrent.futures,hashlib,json,os,time
from pathlib import Path
from rubric import sha,INSTRUCTIONS,TOOLS,canonical
from packets import save,file_sha
from transport import PiAnnotationTransport

def main():
 p=argparse.ArgumentParser();p.add_argument('--packets',type=Path);p.add_argument('--out',type=Path);p.add_argument('--phase',choices=['smoke','main'],default='main');a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True);assert os.environ.get('CUDA_VISIBLE_DEVICES')=='';assert not (a.out/'config.json').exists();
 if a.phase=='smoke':
  smoke_path=Path(__file__).with_name('smoke-packet.json');smoke=json.loads(smoke_path.read_text());rows=[{'packet_sha256':sha(smoke),'path':str(smoke_path),'draw_order':[1,2]}];input_manifest_sha=file_sha(smoke_path)
 else:
  if a.packets is None:raise ValueError('--packets required for main')
  manifest=json.loads((a.packets/'manifest.json').read_text());rows=manifest['packets'];input_manifest_sha=file_sha(a.packets/'manifest.json')
 save(a.out/'config.json',{'phase':a.phase,'packet_manifest_sha256':input_manifest_sha,'protocol_sha256':file_sha(Path(__file__).with_name('protocol.json')),'rubric_semantic_sha256':sha({'instructions':INSTRUCTIONS,'tools':TOOLS}),'scheduled_packets':len(rows),'draws_per_packet':2,'model':'Pi1.5/gpt-6-luna','reasoning':'low','max_output_tokens':1536,'automatic_retries':0,'client_response_cache':False,'pair_sampling':'Separate stateless requests with identical blinded semantic input; model-sample independence not guaranteed.','cost_scope':'Only annotation usage, separate from actor/controller experiment.'})
 start=time.monotonic();results=[]
 if not rows:
  result={'scheduled_packets':0,'observed_packets':0,'complete':True,'scheduled_draws':0,'observed_draws':0,'valid_draws':0,'failed_or_invalid_draws':0,'annotation_request_records':0,'usage_known':0,'input_tokens':0,'output_tokens':0,'elapsed_s':0.0};save(a.out/'result.json',result);save(a.out/'summary.json',{**result,'rows':[]});(a.out/'status.md').write_text('No selected annotation packets; zero calls.\n');print(json.dumps(result));return
 def one(row):
  packet=json.loads((Path(row['path']) if a.phase=='smoke' else a.packets/row['path']).read_text());assert sha(packet)==row['packet_sha256'];folder=a.out/row['packet_sha256'];folder.mkdir();draws=[]
  for draw_id in row['draw_order']:
   client=PiAnnotationTransport();record={'packet_sha256':row['packet_sha256'],'draw_id':draw_id,'separate_fresh_request':True,'other_judge_output_in_input':False}
   try:record.update(client.annotate(packet));record['status']='valid' if not record['validation_errors'] else 'invalid_annotation'
   except Exception as exc:record.update(status='inference_error',error=type(exc).__name__,annotation=None,validation_errors=['inference_error'],request_records=client.calls)
   save(folder/f'draw-{draw_id}.json',record);draws.append(record)
  return {'packet_sha256':row['packet_sha256'],'draws':draws}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4 if a.phase=='main' else 1) as pool:
  futures=[pool.submit(one,row) for row in rows]
  for f in concurrent.futures.as_completed(futures):
   results.append(f.result());calls=[c for r in results for d in r['draws'] for c in d['request_records']];usage=[c.get('provider_usage') or c.get('pi_usage') or {} for c in calls];summary={'scheduled_packets':len(rows),'observed_packets':len(results),'complete':len(results)==len(rows),'scheduled_draws':2*len(rows),'observed_draws':sum(len(r['draws']) for r in results),'valid_draws':sum(d['status']=='valid' for r in results for d in r['draws']),'failed_or_invalid_draws':sum(d['status']!='valid' for r in results for d in r['draws']),'annotation_request_records':len(calls),'usage_known':sum(bool(u) for u in usage),'input_tokens':sum(u.get('input_tokens',u.get('input',0)) for u in usage),'output_tokens':sum(u.get('output_tokens',u.get('output',0)) for u in usage),'elapsed_s':time.monotonic()-start};save(a.out/'result.json',summary);save(a.out/'summary.json',{**summary,'rows':results});(a.out/'status.md').write_text(f"X1 annotation {len(results)}/{len(rows)} packets; valid draws{summary['valid_draws']}; failed/invalid{summary['failed_or_invalid_draws']}; elapsed{summary['elapsed_s']:.1f}s\n");print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
