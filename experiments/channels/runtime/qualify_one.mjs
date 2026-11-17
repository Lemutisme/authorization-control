import { resolve as researchPath } from "../../../pipeline/paths.mjs";
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {Broker} from researchPath("experiments/sealed/evaluation/sealed_control/agent.mjs");
import {episode} from './agent.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
const out=resolve(args['--out']);await mkdir(out,{recursive:true});
const packet=resolve(args['--packet']),bytes=await readFile(packet),source=JSON.parse(bytes);
const broker=new Broker(args['--python'],{script:join(HERE,'fixture_broker.py'),journal:join(out,'rpc-errors.jsonl')});
const row=await episode({'--python':args['--python'],'--manifest':researchPath("experiments/sealed/evaluation/authorship/x2b/manifest-v1.json"),
 '--packet':packet,'--packet-sha256':createHash('sha256').update(bytes).digest('hex'),'--arm':'f0_off','--out':join(out,'episode'),
 '--judge-cache':join(out,'judge'),'--policy-cache':join(out,'policy'),'--actor-cache':join(out,'actor')},{broker});
assert.equal(row.factorial_scientific_status,'known',JSON.stringify(row.factorial_unknown_reasons));
assert.equal(row.source_actor_replay.context_json,source.actor_context_json);assert.equal(row.source_actor_replay.request_json,source.actor_request_json);
assert.equal(row.factorial_first_refusal.same_call_before_update.allowed,false);
assert.equal(row.factorial_first_refusal.update.actual_requests,0);
assert.equal(row.factorial_records.length,1);
const result={unit_id:source.unit_id,passed:true,model_calls:0,external_network_calls:0,source_context_exact:true,
 policy_refused:true,constraint_available:row.factorial_first_refusal.feedback_detail.constraint_available,
 failed_constraint:row.factorial_first_refusal.failed_constraint,actor_new_draws:row.factorial_resources.new_actor_draws,
 native_utility_known:typeof row.native_utility==='boolean'};
await writeFile(join(out,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
