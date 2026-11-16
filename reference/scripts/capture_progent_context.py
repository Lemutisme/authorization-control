"""Reconstruct a failed policy request offline using its frozen adapter and journal."""
import argparse,contextlib,hashlib,importlib.util,io,json,os,socket,sys
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--frozen',type=Path,required=True);p.add_argument('--journal',type=Path,required=True);p.add_argument('--vendor',type=Path,required=True);p.add_argument('--progent',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 os.environ.update(BASELINE_VENDOR=str(a.vendor),PROGENT_SOURCE=str(a.progent),CUDA_VISIBLE_DEVICES='')
 def no_network(*args,**kwargs):raise RuntimeError('Network forbidden during request reconstruction')
 socket.create_connection=no_network;socket.socket.connect=no_network
 spec=importlib.util.spec_from_file_location('failed_adapter',a.frozen/'evaluation/baseline_audit/broker.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 captured=[]
 class Connection:
  def __init__(self,*args,**kwargs):self.endpoint='https://example.invalid/v1/responses';self.key=None;self.calls=[]
 class Capture:
  def __init__(self,*args):self.calls=[]
  def request(self,system,user,temperature=0):captured.append({'system':system,'user':user,'temperature':temperature});return '[]'
  def close(self):pass
 module.PolicyClient=Capture;module.ref.v16.base.LunaTransport=Connection
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
  broker=module.Broker();broker.init({'manifest':str(a.frozen/'manifest.json'),'case_id':'banking__user_task_3__clean','baseline_arm':'progent','model':'gpt-6-luna','delegate_reference':True,'clock_anchor':'2026-11-05T00:00:00','judge_cache':str(a.out.parent/'unused-cache'),'policy_journal':'unused'})
 assert len(captured)==1
 first=next(json.loads(line) for line in a.journal.read_text().splitlines() if json.loads(line)['stage']=='policy_response')
 assert hashlib.sha256(json.dumps(captured[0],sort_keys=True).encode()).hexdigest()==first['request_sha256']
 row={**captured[0],'old_wire_sha256':first['response']['meta']['request_sha256']};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(row)+'\n')
 print(json.dumps({'python_request_matches_failed_journal':True,'network_requests':0,'model_requests':0,'fixture_sha256':hashlib.sha256(a.out.read_bytes()).hexdigest()}))
if __name__=='__main__':main()
