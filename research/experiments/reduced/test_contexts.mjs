import { resolve as researchPath } from "../../pipeline/paths.mjs";
/** Model-free prompt-channel and semantic equivalence qualification. */
import {matchedContext,ARMS,generationStatus} from './draw.mjs';
import {constructorContext} from researchPath("experiments/sealed/evaluation/sealed_control/pi_draw.mjs");
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const sha=s=>createHash('sha256').update(s).digest('hex');
assert.deepEqual(generationStatus({stopReason:'length'},{}),{inferenceUnknown:false,budgetExhausted:true});
assert.deepEqual(generationStatus({stopReason:'error'},{}),{inferenceUnknown:true,budgetExhausted:false});
const protocol=JSON.parse(readFileSync(process.argv[2],'utf8'));
const groups={},rows=[];
for(const unit of protocol.units){
  const source=JSON.parse(readFileSync(unit.runtime_packet,'utf8'));
  const packet={owner_request:source.authentic_owner_request,observations:source.successful_observations,
    contracts:source.registered_contracts,mode:'constructor'};
  for(const arm of ARMS){
    const context=matchedContext(packet,arm,source.original_proposal.function);
    const body=JSON.parse(context.messages[0].content[0].text);
    assert.deepEqual(body.owner_request,packet.owner_request);
    assert.deepEqual(body.observations,packet.observations);
    assert.deepEqual(body.contracts.functions,packet.contracts.functions);
    assert.equal(context.tools.length,1);
    for(const key of ['original_proposal','policy_at_boundary','expected','task_id','unit_id','native_boundary_state'])
      assert.equal(Object.hasOwn(body,key),false);
    if(arm==='all_tools_complete')assert.deepEqual(context,constructorContext(packet));
    else assert.equal(body.required_function,'send_money');
    const digest=sha(JSON.stringify(context));
    const key=unit.context_group+'|'+arm;(groups[key]??=new Set()).add(digest);
    rows.push({unit_id:unit.unit_id,context_group:unit.context_group,arm,context_sha256:digest,
      original_constructor_context_equal:arm==='all_tools_complete'?JSON.stringify(context)===JSON.stringify(constructorContext(packet)):null});
  }
}
assert.equal(Object.keys(groups).length,6);
for(const hashes of Object.values(groups))assert.equal(hashes.size,1);
const result={passed:true,checked:rows.length,unique_contexts:Object.keys(groups).length,
  unchanged_owner_observations_and_tool_definitions:true,arm_A_frozen_context_identical:true,model_calls:0,rows};
if(process.argv[3])writeFileSync(process.argv[3],JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({...result,rows:undefined}));
