"""Model-free continuation checks for every frozen symmetric packet."""
import json
import subprocess
import sys
from pathlib import Path
from native import PanelBroker, canonical

HERE = Path(__file__).resolve().parent


def main():
    manifest = json.loads((HERE/'frozen-v1/manifest.json').read_text())
    rows = []
    noops = []
    for ref in manifest['rows']:
        packet = json.loads(Path(ref['path']).read_text())
        correction = PanelBroker(packet, actor_correct=False, gate_correct=True, feedback='value_free')
        assert correction.pending_response['is_error'] is True
        assert correction.env.model_dump(mode='json') == packet['native_boundary_state']
        repaired = correction.invoke(packet['correct_proposal'], 'correct_after_refusal')
        assert repaired['is_error'] is False
        result = correction.finish()
        assert result['correct_selected_effect'] is True
        assert result['wrong_selected_effect'] is False
        corruption = PanelBroker(packet, actor_correct=True, gate_correct=False, feedback='value_stating')
        assert corruption.pending_response['is_error'] is True
        assert corruption.env.model_dump(mode='json') == packet['native_boundary_state']
        adopted = corruption.invoke(packet['faulty_proposal'], 'wrong_after_refusal')
        assert adopted['is_error'] is False
        result = corruption.finish()
        expected = packet['cells']['actor_wrong__gate_wrong']['native_reference']['selected_effect_observed']
        assert result['fault_selected_effect'] == expected
        if not expected:
            noops.append(packet['packet_id'])
        # The two feedback strings are identical after removal of exactly one
        # serialized constraint clause. Names and the retry instruction stay fixed.
        for cell in ['actor_wrong__gate_correct', 'actor_correct__gate_wrong']:
            decisions = packet['cells'][cell]['decision']
            restriction = decisions['value_stating']['failed_restriction']
            clause = ' Policy constraint: ' + json.dumps(restriction, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '.'
            assert decisions['value_stating']['feedback'].replace(clause, '', 1) == decisions['value_free']['feedback']
        rows.append({'packet_id': packet['packet_id'], 'correction_executable': True,
                     'corruption_executable': True, 'fault_selected_effect_observable': expected})
    # Verify the process boundary/API on one packet, including a genuinely denied
    # pending call followed by a native correction, without any model interaction.
    packet = json.loads(Path(manifest['rows'][0]['path']).read_text())
    requests = [
        {'id': 1, 'method': 'init', 'params': {'packet': manifest['rows'][0]['path'], 'actor_correct': False, 'gate_correct': True, 'feedback': 'value_free'}},
        {'id': 2, 'method': 'invoke', 'params': {**packet['correct_proposal'], 'call_id': 'cli_correct'}},
        {'id': 3, 'method': 'finish', 'params': {'final_text': ''}},
    ]
    process = subprocess.run([sys.executable, '-B', str(HERE/'native.py')], input=''.join(json.dumps(q)+'\n' for q in requests),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert len(responses) == 3 and all(r['ok'] for r in responses)
    assert responses[-1]['result']['correct_selected_effect'] is True
    output = {'packets_checked': len(rows), 'off_diagonal_native_continuations': len(rows)*2,
              'pending_refusals_leave_state_unchanged': True, 'all_correct_retries_execute_correct_effect': True,
              'matched_feedback_only_value_clause_differs': True, 'cli_roundtrip_passed': True,
              'fault_selected_field_noops': noops, 'rows': rows, 'model_calls': 0, 'network_calls': 0}
    (HERE/'continuation-check.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({k: v for k, v in output.items() if k != 'rows'}, indent=2))


if __name__ == '__main__':
    main()
