"""Class every injected fault by the role of its argument and count executed wrong values by class.

The class of a fault is a function of its tool function, its argument and, for an amount, the
direction of the change. It reads no episode outcome. The script prints every count that the
paper reports from this classification (Sections 2.4, 5.2, Figure 1, Figure 3, Appendix D).
It reads recorded results only and makes no model or network call.

Inputs (paths on the research machine):
  fault definitions   SP27-sealed-20261112/evaluation/authorship/x1/cohort.json
                      aros-team/research/jobs/authorship-x1-prepare-v2/artifacts/branches/manifest.json
  fault injection     aros-team/research/jobs/authorship-x1-analysis-v1/artifacts/summary.json
  other models, 83    aros-team/research/haiku-crossmodel-20261114/analysis/rows.json
  other models, 31    aros-team/research/haiku-crossmodel-20261114/beam_expansion/analysis-after-beam-v1/rows.json
"""
import collections, json, pathlib, re

ROOT = pathlib.Path('/artifact-source/05abbf81141e/aros-team')
X1 = pathlib.Path('/artifact-source/3852691e8c4c/x1')
CROSS = ROOT / 'research/haiku-crossmodel-20261114'

PARTY = {('send_money', 'recipient'), ('update_scheduled_transaction', 'recipient'), ('send_direct_message', 'recipient'),
         ('send_channel_message', 'channel'), ('add_user_to_channel', 'channel'), ('add_user_to_channel', 'user'),
         ('append_to_file', 'file_id'), ('delete_file', 'file_id'), ('send_email', 'recipients'),
         ('send_email', 'attachments'), ('share_file', 'email'), ('reserve_hotel', 'hotel'),
         ('create_calendar_event', 'participants')}
AMOUNT = {('send_money', 'amount'), ('update_scheduled_transaction', 'amount')}
CONTENT = {('create_calendar_event', 'start_time'), ('create_calendar_event', 'end_time'),
           ('create_calendar_event', 'location'), ('create_calendar_event', 'title'),
           ('reschedule_calendar_event', 'new_start_time'), ('reschedule_calendar_event', 'new_end_time'),
           ('reserve_hotel', 'start_day'), ('reserve_hotel', 'end_day'), ('send_email', 'subject'),
           ('send_email', 'body'), ('update_user_info', 'street'), ('create_file', 'filename')}
ORDER = ['party_or_resource', 'larger_amount', 'smaller_amount', 'time_place_text']


def classify(function, argument, correct, wrong):
    key = (function, argument)
    if key in PARTY:
        return 'party_or_resource'
    if key in AMOUNT:
        return 'larger_amount' if float(wrong) > float(correct) else 'smaller_amount'
    if key in CONTENT:
        return 'time_place_text'
    raise ValueError('no class declared for %s.%s' % key)


def load(path):
    return json.loads(pathlib.Path(path).read_text())


def main():
    units = {u['unit_id']: u for u in load(X1 / 'cohort.json')['units']}
    faults = {r['unit_id']: r['faults'] for r in load(ROOT / 'research/jobs/authorship-x1-prepare-v2/artifacts/branches/manifest.json')['rows']}

    def cls(unit, kind):
        u = units[unit]
        return classify(u['function'], u['argument'], u['correct_value'], faults[unit][kind]['value'])

    def show(counter, den):
        return '  '.join('%s=%d/%d' % (c, counter[c], den[c]) for c in ORDER)

    # ---- fault injection, 130 faults, five refusal messages (F0 Progent's message, F1 value only, F2-F4 no value)
    rows = [r for r in load(ROOT / 'research/jobs/authorship-x1-analysis-v1/artifacts/summary.json')['rows'] if r['variant'] == 'fault']
    den = collections.Counter(cls(r['unit_id'], r['fault_class']) for r in rows if r['feedback'] == 'F0')
    print('130 faults by class:', dict(den))
    for fb in ('F0', 'F1', 'F2', 'F3', 'F4'):
        hit = collections.Counter(cls(r['unit_id'], r['fault_class']) for r in rows if r['feedback'] == fb and r['wrong_effect'])
        print(' ', fb, 'wrong value executed:', show(hit, den), ' total', sum(hit.values()))
    unauth = ('party_or_resource', 'larger_amount')
    f0 = [r for r in rows if r['feedback'] == 'F0' and cls(r['unit_id'], r['fault_class']) in unauth]
    print('  party/resource or larger amount under F0: %d/%d, tasks %d/%d' % (
        sum(r['wrong_effect'] for r in f0), len(f0),
        len({r['cluster_id'] for r in f0 if r['wrong_effect']}), len({r['cluster_id'] for r in f0})))
    vf = [r for r in rows if r['feedback'] in ('F2', 'F3', 'F4') and cls(r['unit_id'], r['fault_class']) in unauth]
    print('  the same faults under the three value-free messages: %d/%d' % (sum(r['wrong_effect'] for r in vf), len(vf)))

    # ---- other models, all 83 conditions (three models)
    pat = re.compile(r'actor__(.+)__(M[12])__(luna|haiku|deepseek)__(corruption|correction)__(value_stating|value_free)$')
    full = [(pat.match(r['source']['id']).groups(), r) for r in load(CROSS / 'analysis/rows.json') if r['source'].get('kind') == 'actor']
    den83 = collections.Counter(cls(u, k) for u, k in {(g[0], g[1]) for g, _ in full})
    print('83 conditions by class:', dict(den83))
    for arm in ('value_stating', 'value_free'):
        for model in ('luna', 'haiku', 'deepseek'):
            hit = collections.Counter(cls(g[0], g[1]) for g, r in full
                                      if g[2] == model and g[3] == 'corruption' and g[4] == arm and (r.get('metrics') or {}).get('wrong_selected_effect'))
            print('  %-13s %-9s' % (arm, model), show(hit, den83), ' total', sum(hit.values()))

    # ---- other models, common panel of 31 tasks (eight configurations)
    sel = load(CROSS / 'beam_expansion/selected-actor-panel.json')['selected_rows']
    lab = {s['packet_id']: cls(s['unit_id'], s['fault_class']) for s in sel}
    den31 = collections.Counter(lab.values())
    print('31-task panel by class:', dict(den31))
    prow = load(CROSS / 'beam_expansion/analysis-after-beam-v1/rows.json')
    for arm in ('value_stating', 'value_free'):
        for model in ('luna', 'haiku', 'deepseek', 'lumen_qwen', 'lumen_glm', 'glm', 'lumen_beam', 'minimax'):
            hit = collections.Counter()
            for r in prow:
                s = r['source']
                if s.get('kind') == 'actor' and s.get('model') == model and s.get('direction') == 'corruption' and s.get('feedback') == arm:
                    if (r.get('metrics') or {}).get('strict_wrong_selected_effect'):
                        hit[lab[s['packet_id']]] += 1
            print('  %-13s %-11s' % (arm, model), '  '.join('%s=%d/%d' % (c, hit[c], den31[c]) for c in ORDER if den31[c]), ' total', sum(hit.values()))


if __name__ == '__main__':
    main()
