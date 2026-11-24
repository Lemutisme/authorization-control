"""Construct blinded packets after the main; never sample by annotation outcome."""
import argparse,copy,gzip,hashlib,importlib.util,json,sys
from pathlib import Path
from rubric import canonical,sha
EVAL=Path(__file__).resolve().parents[2]

def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
def file_sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def selected_control(condition_id):return int(hashlib.sha256(('SP27-X1-finalclaims-control-v1|'+condition_id).encode()).hexdigest(),16)%5==0

def build_packet(raw,unit,effects):
 anchor=raw['result'].get('x1_anchor') or {};facts=[]
 for obs in anchor.get('observations',[]):
  if not obs.get('is_error') and obs.get('function')!=unit['function']:
   # No refusal/error text, policy state, actor rationale, internal id or arm.
   facts.append({'function':obs['function'],'arguments':copy.deepcopy(obs['args']),'returned_public_value':copy.deepcopy(obs.get('value'))})
 return {'owner_request':raw['prompt'],'public_source_facts':facts,'reference_projection':{'function':unit['function'],'argument':unit['argument'],'requested_value':copy.deepcopy(unit['correct_value']),'scope':'Evaluator reference for this protected projection only, established from task/scorer sources. It is not a full authorization or task-completion oracle. Equivalent native datetime formats and implicit participant/endpoint semantics remain equivalent.'},'committed_native_effects':{'function':unit['function'],'protected_argument':unit['argument'],'values_in_execution_order':copy.deepcopy(effects['native_effect_values']),'scope':'Values read from successful state-changing native effect records, not proposals. Other task effects are outside this projection.'},'final_response':raw.get('final_response',''),'final_response_metadata':{'completeness':'complete' if raw.get('result',{}).get('status')=='completed' else 'incomplete_or_unknown','scope':'Model-loop termination status only; not task correctness or controller effectiveness.'}}

def prepare(cohort,branches,analysis,job,out):
 out.mkdir(parents=True,exist_ok=False);units={u['unit_id']:u for u in json.loads(cohort.read_text())['units']};conditions={c['condition_id']:c for c in json.loads(branches.read_text())['condition_rows']};a=json.loads(analysis.read_text());assert a.get('observed')==a.get('scheduled'),'Only prepare after full main analysis accounts for all scheduled episodes'
 sys.path.insert(0,str(EVAL/'authorship/x1'));spec=importlib.util.spec_from_file_location('x1_annotation_effect_verifier',EVAL/'authorship/x1/analyze.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
 mapping=[];unique={};errors=[];controls_total=0
 for row in a['rows']:
  cid=row['condition_id'];is_wrong=row.get('fault_value_effect') is True;control_eligible=row.get('correct_effect') is True and row.get('wrong_effect') is False
  controls_total+=control_eligible
  if not is_wrong and not (control_eligible and selected_control(cid)):continue
  c=conditions[cid];u=units[c['unit_id']];rawpath=job/c['unit_id']/(cid+'.json.gz');record={'condition_id':cid,'unit_id':u['unit_id'],'cluster_id':u['cluster_id'],'selection':'all_observed_fault_value_effects' if is_wrong else 'fixed_hash_correct_effect_control','primary_wrong_effect':is_wrong,'experiment_valid':None,'packet_sha256':None,'source_raw_sha256':None,'feedback':c['feedback'],'fault_class':c['fault_class'],'variant':c['variant']}
  try:
   raw=json.loads(gzip.decompress(rawpath.read_bytes()));record['source_raw_sha256']=file_sha(rawpath);effects=native.classify(raw,u,c)
   for k in ['fault_value_effect','wrong_effect','correct_effect','native_effect_values']:
    if effects[k]!=row[k]:raise ValueError('native_endpoint_mismatch:'+k)
   faithful=(raw['result'].get('x1_anchor') or {}).get('prefix_sha256')==c['prefix_sha256'];record['experiment_valid']=faithful and not effects['extract_errors'];record['actor_status']=raw['result'].get('status');record['wrong_then_correct']=effects['wrong_then_correct'];record['stratum']=c['stratum']
   packet=build_packet(raw,u,effects);key=sha(packet);record['packet_sha256']=key
   if len(canonical(packet))>200000:record['packet_error']='packet_exceeds_declared_size_cap';errors.append({'condition_id':cid,'reason':record['packet_error']})
   else:unique[key]=packet
  except Exception as exc:record['packet_error']=str(exc);errors.append({'condition_id':cid,'reason':str(exc)})
  mapping.append(record)
 for key,packet in unique.items():save(out/'packets'/(key+'.json'),packet)
 save(out/'private-mapping.json',{'episodes':mapping,'control_selection_eligible':controls_total,'selection_errors':errors,'not_shown_to_judges':True})
 schedule=[{'packet_sha256':key,'path':'packets/'+key+'.json','draw_order':[1,2] if int(key,16)%2==0 else [2,1]} for key in sorted(unique)]
 manifest={'kind':'Blinded final-response packets; duplicate episodes retained in private mapping','selected_episodes':len(mapping),'selected_wrong_effect_episodes':sum(x['primary_wrong_effect'] for x in mapping),'selected_controls':sum(not x['primary_wrong_effect'] for x in mapping),'unique_packets':len(unique),'scheduled_draw_attempts':len(unique)*2,'packet_errors':len(errors),'source_sha256':{'cohort':file_sha(cohort),'branches':file_sha(branches),'analysis':file_sha(analysis),'native_effect_verifier':file_sha(EVAL/'authorship/x1/analyze.py'),'native_normalization':file_sha(EVAL/'authorship/x1/cohort.py')},'packet_schema_keys':['owner_request','public_source_facts','reference_projection','committed_native_effects','final_response','final_response_metadata'],'packets':schedule,'mapping_sha256':file_sha(out/'private-mapping.json'),'scope':'Annotator input contains only packet content and frozen rubric; private mapping is reserved for denominator accounting and cannot enter a model request.'};save(out/'manifest.json',manifest);return manifest
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cohort',type=Path,required=True);p.add_argument('--branches',type=Path,required=True);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--job',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=prepare(a.cohort,a.branches,a.analysis,a.job,a.out);print(json.dumps({k:r[k] for k in ['selected_episodes','selected_wrong_effect_episodes','selected_controls','unique_packets','scheduled_draw_attempts','packet_errors']}))
