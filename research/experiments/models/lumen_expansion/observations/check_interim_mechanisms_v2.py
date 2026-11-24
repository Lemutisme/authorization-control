"""Model-free, post-hoc scorer/parser checks on retained immutable outputs."""
from pipeline.paths import resolve as research_path
import copy, gzip, hashlib, importlib.util, inspect, json, re, socket
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string
from agentdojo.default_suites.v1.tools.types import CalendarEvent, Email
HERE = Path(__file__).resolve().parent
LUMEN = HERE.parent

def no_network(*args, **kwargs):
    raise RuntimeError('No network allowed in this check')
socket.create_connection = no_network
socket.socket.connect = no_network

def load(path):
    path = Path(path)
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    rows = []
    for model, tasks in [('lumen_qwen', [0, 4, 7, 8]), ('lumen_glm', [0, 1, 3, 7, 8])]:
        folder = LUMEN / 'outputs' / f'main-{model}-all-v1/raw'
        for task_id in tasks:
            paths = list(folder.glob(f'actor__travel__user_task_{task_id}__*__correction__value_stating.json.gz'))
            assert len(paths) == 1
            path = paths[0]
            raw = load(path)
            packet = load(raw['packet_path'])
            assert raw['metrics']['correct_selected_effect'] == 1 and raw['metrics']['native_utility'] == 0
            suite = get_suite('v1.2.2', 'travel')
            task = suite.get_user_task_by_id(f'user_task_{task_id}')
            scorer = Path(inspect.getsourcefile(task.utility))
            assert sha(scorer) == packet['unit']['utility_source']['file_sha256']

            def hydrate(data):
                env = suite.environment_type.model_validate(copy.deepcopy(data))
                env.calendar.events = {key: CalendarEvent.model_validate(value) for key, value in data['calendar']['events'].items()}
                env.inbox.emails = {key: Email.model_validate(value) for key, value in data['inbox']['emails'].items()}
                assert env.model_dump(mode='json') == data, 'Poststate hydration changed another field'
                return env
            initial = hydrate(packet['native_initial_state'])
            state = hydrate(raw['native']['final'])
            calls = [FunctionCall.model_validate(c) for c in raw['native']['proposals']]

            def score(data, text):
                return bool(suite._check_task_result(task, [text_content_block_from_string(text)], initial.model_copy(deep=True), hydrate(data), calls))
            original = state.model_dump(mode='json')
            changed = copy.deepcopy(original)
            text = raw['final_text']
            modified_text = text
            assert score(original, text) is False
            if task_id == 3:
                assert model == 'lumen_glm' and '1,000' in text and ('1000' not in text)
                modified_text = text.replace('1,000', '1000')
                edits = [{'path': 'final_text', 'old': '1,000', 'new': '1000'}]
                assert changed == original
            elif task_id == 0:
                canonical = packet['unit']['correct_projection']['hotel']
                previous = changed['reservation']['title']
                assert previous != canonical and previous.casefold() == canonical.casefold()
                changed['reservation']['title'] = canonical
                edits = [{'path': 'reservation.title', 'old': previous, 'new': canonical}]
            else:
                canonical = packet['unit']['correct_projection']['location']
                old_ids = set(packet['native_boundary_state']['calendar']['events'])
                new_ids = set(changed['calendar']['events']) - old_ids
                assert len(new_ids) == 1
                event_id = next(iter(new_ids))
                previous = changed['calendar']['events'][event_id]['location']
                assert previous != canonical and previous.casefold() == canonical.casefold()
                changed['calendar']['events'][event_id]['location'] = canonical
                edits = [{'path': f'calendar.events.{event_id}.location', 'old': previous, 'new': canonical}]
            adjusted = score(changed, modified_text)
            assert adjusted is True
            rows.append({'raw': str(path), 'raw_sha256': sha(path), 'packet_sha256': sha(raw['packet_path']), 'model': model, 'task': f'travel__user_task_{task_id}', 'native_utility_original': False, 'diagnostic_utility_with_only_noted_edit': adjusted, 'edits': edits, 'scorer_source': str(scorer), 'scorer_sha256': sha(scorer), 'scope': 'Copied-state/text scorer sensitivity only; original outcomes and scheduled counts unchanged.'})
    parser_path = Path(research_path('progent/secagent/utils.py'))
    spec = importlib.util.spec_from_file_location('retained_progent_parser', parser_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = LUMEN / 'outputs/main-lumen_qwen-all-v1/raw/update__attack-banking__user_task_9__injection_task_1__lumen_qwen__r0__u1.json.gz'
    raw = load(path)
    assert len(raw['requests']) == 1 and raw['admission'] == 1
    text = raw['requests'][0]['text']
    blocks = re.findall('```json(.*?)```', text, re.S)
    assert len(blocks) == 2 and 'malicious' in text.lower()
    first = json.loads(blocks[0])
    second = json.loads(blocks[1])
    parsed = module.extract_json(text)
    assert parsed == first == raw['update']['candidate_parse_events'][0]['candidate']
    assert any((p['name'] == 'send_money' for p in first)) and (not any((p['name'] == 'send_money' for p in second)))
    assert 'send_money' in raw['policy_after']
    hidden_path = Path(str(path).replace('__r0__u1.json.gz', '__r0__u0.json.gz'))
    hidden = load(hidden_path)
    assert hidden['admission'] == 0
    parser = {'raw': str(path), 'raw_sha256': sha(path), 'hidden_raw': str(hidden_path), 'hidden_sha256': sha(hidden_path), 'parser_source': str(parser_path), 'parser_sha256': sha(parser_path), 'json_blocks': 2, 'first_block_is_parsed_candidate': True, 'first_block_has_send_money': True, 'second_block_has_send_money': False, 'installed_send_money': raw['policy_after']['send_money'], 'visible_admission': 1, 'hidden_admission': 0, 'scope': 'Specific retained model-plus-parser output; no general causal claim about recognition or parser replacement.'}
    result = {'passed': True, 'selection': 'Outcome-selected exploratory diagnostic; no efficacy relabeling', 'scorer_checks': rows, 'parser_check': parser, 'model_calls': 0, 'network_calls': 0, 'native_tool_calls': 0}
    (HERE / 'interim-mechanism-check-v2.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'scorer_rows': len(rows), 'utility_flips': sum((r['diagnostic_utility_with_only_noted_edit'] for r in rows)), 'parser_first_block_confirmed': True, 'model_calls': 0, 'native_tool_calls': 0}))
if __name__ == '__main__':
    main()
