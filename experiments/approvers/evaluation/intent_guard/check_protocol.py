"""Subprocess control: native diagnostic stdout must not become an RPC message."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path

CHILD='''import sys
sys.path.insert(0,sys.argv[1])
import broker
original=broker.Broker.finish
def noisy(self,p):
    print("controlled native diagnostic")
    return original(self,p)
broker.Broker.finish=noisy
broker.main()
'''

def run(folder,manifest,case):
    child=subprocess.Popen([sys.executable,'-B','-c',CHILD,str(folder)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    def rpc(ident,method,params):
        child.stdin.write(json.dumps({'id':ident,'method':method,'params':params})+'\n');child.stdin.flush()
        result=json.loads(child.stdout.readline())
        assert result['id']==ident and result['ok'];return result['result']
    try:
        # Initialization contains private transport settings. Never print or save it.
        rpc(1,'init',{'manifest':str(manifest),'case_id':case,'arm':'none','model':'gpt-6-luna'})
        result=rpc(2,'finish',{'final_text':''})
        expected=hashlib.sha256(b'controlled native diagnostic\n').hexdigest()
        events=result['result'].get('native_stdout_diagnostics',[])
        return {'protocol_valid':True,'diagnostic_hash_recorded':any(x['sha256']==expected for x in events)}
    except json.JSONDecodeError:return {'protocol_valid':False,'error_type':'JSONDecodeError'}
    finally:
        child.stdin.close();child.terminate()
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:child.kill();child.wait()

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--old-broker',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    cases=json.loads(a.manifest.read_text())['cases'];case=next(c['case_id'] for c in cases if c['condition']=='clean')
    old=run(a.old_broker.resolve(),a.manifest.resolve(),case);fixed=run(Path(__file__).resolve().parent,a.manifest.resolve(),case)
    passed=old['protocol_valid'] is False and fixed['protocol_valid'] is True and fixed['diagnostic_hash_recorded'] is True
    report={'kind':'Native diagnostic/protocol isolation negative control; no model or native tool effect','old':old,'fixed':fixed,'passed':passed}
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if not passed:raise SystemExit(1)
if __name__=='__main__':main()
