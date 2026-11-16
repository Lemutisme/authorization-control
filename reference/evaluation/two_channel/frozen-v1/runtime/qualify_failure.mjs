/** Actual Pi/RPC failure handling with synthetic Responses events, no sockets. */
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {Broker} from '/artifact-source/39fa1b622d22/agent.mjs';
import {episode} from './agent.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
const out=resolve(args['--out']),kind=process.env.CHANNELS_QUALIFICATION_FAILURE;
assert(['actor_transport','actor_length','actor_budget','policy_transport','policy_length'].includes(kind));
await mkdir(out,{recursive:true});
const packet=resolve(args['--packet']),bytes=await readFile(packet);
const broker=new Broker(args['--python'],{script:join(HERE,'fixture_broker.py'),journal:join(out,'rpc-errors.jsonl')});
const row=await episode({'--python':args['--python'],'--manifest':'/artifact-source/968854d6265c/manifest-v1.json',
 '--packet':packet,'--packet-sha256':createHash('sha256').update(bytes).digest('hex'),'--arm':kind.startsWith('policy')?'f0_u0':'f0_off','--out':join(out,'episode'),
 '--judge-cache':join(out,'judge'),'--policy-cache':join(out,'policy'),'--actor-cache':join(out,'actor')},{broker});
assert.equal(typeof row.native_utility,'boolean','Keep realized native endpoint despite behavioral/transport stop');
assert.equal(row.factorial_first_refusal.same_call_before_update.allowed,false);
const transport=kind.endsWith('transport');
assert.equal(row.factorial_scientific_status,transport?'operationally_unknown':'known',JSON.stringify(row.factorial_unknown_reasons));
if(kind==='actor_length')assert.equal(row.actor_status,'output_limit');
if(kind==='actor_budget'){
 assert.equal(row.actor_status,'model_round_limit');
 assert.equal(row.factorial_resources.actor_budget_slots,16);
 assert.equal(row.factorial_records.length,1+row.factorial_resources.new_actor_draws);
}
if(kind==='actor_transport')assert(row.factorial_unknown_reasons.includes('actor_transport_failure'));
if(kind==='policy_transport')assert(row.factorial_unknown_reasons.includes('policy_transport_failure'));
if(kind==='policy_length')assert.equal(row.factorial_resources.policy_output_limits,6);
if(kind.startsWith('policy'))assert.equal(row.factorial_first_refusal.update.actual_requests,6);
const result={kind,passed:true,status:row.actor_status,scientific_status:row.factorial_scientific_status,
 unknown_reasons:row.factorial_unknown_reasons,resources:row.factorial_resources,model_calls:0,external_network_calls:0};
await writeFile(join(out,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
