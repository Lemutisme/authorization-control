/** Actual Pi/SSE -> Python -> original native checks, with scripted replies only. */
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {Broker} from '/artifact-source/39fa1b622d22/agent.mjs';
import {episode,ARMS} from './agent.mjs';
const HERE=dirname(fileURLToPath(import.meta.url));
const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
const out=resolve(args['--out']);await mkdir(out,{recursive:true});
const packet=resolve(args['--packet']),packetBytes=await readFile(packet),source=JSON.parse(packetBytes);
assert.equal(process.env.CHANNELS_QUALIFICATION_PACKET,packet);
const rows=[];
for(const arm of ARMS){
 const folder=join(out,arm);await mkdir(folder,{recursive:true});
 const broker=new Broker(args['--python'],{journal:join(folder,'rpc-errors.jsonl'),script:join(HERE,'fixture_broker.py')});
 const row=await episode({'--python':args['--python'],'--manifest':args['--manifest']||'/artifact-source/968854d6265c/manifest-v1.json',
  '--packet':packet,'--packet-sha256':createHash('sha256').update(packetBytes).digest('hex'),'--arm':arm,'--out':join(folder,'episode'),
  '--judge-cache':join(folder,'judge'),'--policy-cache':join(out,'shared-policy'),'--actor-cache':join(out,'shared-actor')},{broker});
 const raw=JSON.parse(gunzipSync(await readFile(join(folder,'episode.json.gz'))));
 assert.equal(row.factorial_scientific_status,'known',JSON.stringify(row.factorial_unknown_reasons));
 assert.equal(row.status,'completed');assert.equal(row.source_actor_replay.actual_network_call,false);
 assert.equal(row.source_actor_replay.context_json,source.actor_context_json);
 assert(row.factorial_resources.actor_budget_slots<=16);assert(row.factorial_resources.total_policy_budget_slots<=64);
 const first=row.factorial_first_refusal;
 assert.equal(first.refusal_ordinal,1);assert(first.refusal_state_unchanged);
 assert.equal(first.same_call_before_update.allowed,false);
 assert(first.feedback_detail.constraint_available);
 assert.equal(first.feedback_detail.constraint_disclosed,arm.startsWith('f1'));
 assert.equal(first.new_admission,arm.endsWith('u1'));
 if(arm.endsWith('off')){assert.equal(first.update.actual_requests,0);assert.equal(first.update.kind,'refusal_update_disabled_reference');}
 else{
  assert.equal(first.update.actual_requests,1);
  assert.equal(first.update.selector_model_calls,0);
  assert.equal(first.update.public_call_params.length,arm.endsWith('u1')?1:0);
 }
 const newTransactions=raw.final.bank_account.transactions.filter(t=>!source.native_boundary_state.bank_account.transactions.some(old=>old.id===t.id));
 const expected=arm==='f0_u1'?200.29:arm==='f1_u0'||arm==='f1_off'?195.29:null;
 assert.deepEqual(newTransactions.map(t=>t.amount),expected===null?[]:[expected]);
 assert.equal(row.native_utility,arm==='f0_u1');
 rows.push({arm,first_update_new_admission:first.new_admission,native_amounts:newTransactions.map(t=>t.amount),
  utility:row.native_utility,resources:row.factorial_resources,first_update:first.update,
  actor_request:row.pi.calls[0].wire_request_json,feedback:first.actor_feedback});
}
for(const value of ['f0','f1']){
 const subset=rows.filter(r=>r.arm.startsWith(value));
 assert(subset.every(r=>r.actor_request===subset[0].actor_request),'B must not change the first actor request');
 assert(subset.every(r=>r.feedback.text===subset[0].feedback.text));
}
for(const u of ['u0','u1']){
 const subset=rows.filter(r=>r.arm.endsWith(u));
 assert.deepEqual(subset[0].first_update.public_call_params,subset[1].first_update.public_call_params);
 assert.deepEqual(subset[0].first_update.policy_before,subset[1].first_update.policy_before);
}
const http=(await readFile(process.env.CHANNELS_QUALIFICATION_JOURNAL,'utf8')).trim().split('\n').map(JSON.parse);
assert(http.every(r=>r.wire_json.includes('"model":"gpt-6-luna"')));
assert(http.filter(r=>r.role==='policy').every(r=>JSON.parse(r.wire_json).max_output_tokens===8192));
assert(http.filter(r=>r.role==='actor').every(r=>JSON.parse(r.wire_json).max_output_tokens===1400));
const report={passed:true,arms:rows.map(({first_update,actor_request,feedback,...r})=>r),
 fake_http_requests:http.length,new_model_calls:0,external_network_calls:0,
 scope:'Native source replay, actual official Pi/SSE and RPC; fake actor and generator responses are qualification fixtures, not efficacy outcomes.'};
await writeFile(join(out,'result.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
