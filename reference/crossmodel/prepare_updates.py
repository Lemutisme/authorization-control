"""Freeze the existing 136 refusal states for a new generator-family contrast."""
import copy, gzip, hashlib, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = Path('/artifact-source/6a55f9f127d3/two_channel')


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    protocol = json.loads((SOURCE/'frozen-v1/protocol-main.json').read_text())
    out = HERE/'updates/packets'
    out.mkdir(parents=True, exist_ok=True)
    index = []
    for unit in protocol['units']:
        rawpath = SOURCE/'outputs/main-v1'/unit['unit_id']/'repetition-0/f0_u0.json.gz'
        raw = json.loads(gzip.decompress(rawpath.read_bytes()))
        source = raw['factorial_source_packet']
        first = raw['result']['factorial_first_refusal']
        context = json.loads(raw['result']['policy_calls'][0]['context_json'])
        content = context['messages'][0]['content']
        tools = json.loads(content.split('TOOLS: ', 1)[1].split('\nUSER_QUERY: ', 1)[0])
        # Node serialization erased integral-float spellings in state fields;
        # the actual retained model request preserves them. Restore priority100
        # rule arguments from that request before regenerating its exact text.
        policy=copy.deepcopy(first['decision_policy'])
        generated=json.loads(content.split('\nCURRENT_RESTRICTIONS: ',1)[1])
        positions={}
        for rule in generated:
            name=rule['name'];candidates=[r for r in policy[name] if r[0]>=100]
            position=positions.get(name,0);candidates[position][2]=copy.deepcopy(rule['args']);positions[name]=position+1
        packet = {'unit_id': unit['unit_id'], 'panel': unit['panel'], 'task_id': unit['task_id'],
                  'case_id': unit['case_id'], 'suite': source['suite'],
                  'owner_request': source['authentic_owner_request'],
                  'policy': policy, 'policy_numeric_recovery':'Priority100 arguments restored from exact retained first updater request; semantics unchanged.',
                  'state': source['native_boundary_state'],
                  'original_proposal': source['original_proposal'], 'proposal': first['proposal'],
                  'tools': tools, 'system_prompt': context['systemPrompt'],
                  'reference_hidden_context': context, 'tool_result': first['update']['tool_result'],
                  'historical_constructor_calls': source['historical_constructor_calls'],
                  'source_raw': str(rawpath), 'source_raw_sha256': sha(rawpath),
                  'source_packet_sha256': hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()}
        path = out/(unit['unit_id']+'.json')
        path.write_text(json.dumps(packet, ensure_ascii=False, indent=2)+'\n')
        index.append({'unit_id': unit['unit_id'], 'panel': unit['panel'], 'task_id': unit['task_id'],
                      'packet': str(path), 'sha256': sha(path)})
    result = {'scope': 'First forced regeneration only, at the same 136 frozen refusal states; no actor continuation.',
              'source_research_commit': '778ba8fb6e0b4e9b2676de303537e4e055fa78f3', 'units': index}
    (HERE/'updates/index.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'units': len(index), 'panels': {p:sum(u['panel']==p for u in index) for p in ['honest_fault','attack','honest_natural']}}))


if __name__ == '__main__': main()
