"""Derive all X2 tables from raw per-arm episode records; never pool panels."""
import argparse
import gzip
import json
from pathlib import Path
from prepare import save
from run import aggregate


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runs', type=Path, nargs='+', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    table, configs, keyed = [], [], {}
    for run in a.runs:
        config = json.loads((run / 'config.json').read_text())
        assert not config['model_free_scripted'], 'Scripted qualification is not a scientific outcome'
        configs.append(config)
        arm, panel = config['arm'], config['panel']
        key = (panel, arm, config['phase'])
        assert key not in keyed, 'Do not silently merge recovery or repeated runs'
        rows = []
        for cid in config['cases']:
            raw = run / cid / (arm + '.json.gz')
            if raw.exists():
                r = json.loads(gzip.decompress(raw.read_bytes()))['result']
                assert r['fresh_actor'] is False and r['arm'] == arm and r['panel'] == panel
            else:
                r = {'case_id': cid, 'status': 'missing_episode', 'steps': []}
            rows.append(r)
        keyed[key] = {r['case_id']: r for r in rows}
        table.append({'run': str(run), 'phase': config['phase'], 'panel': panel, 'arm': arm,
                      **aggregate(rows, len(config['cases']))})
    paired = []
    for panel in ['post_exposure', 'initial']:
        for phase in ['smoke', 'main']:
            auto, narrow = keyed.get((panel, 'auto_approve', phase)), keyed.get((panel, 'narrow_only', phase))
            if auto is None or narrow is None:
                continue
            assert set(auto) == set(narrow)
            mismatches, unknown = [], []
            for cid in auto:
                aa, nn = auto[cid], narrow[cid]
                if not aa.get('steps') or not nn.get('steps'):
                    unknown.append(cid)
                    continue
                if aa['steps'][0]['allowed'] != nn['steps'][0]['allowed']:
                    mismatches.append(cid)
            paired.append({'panel': panel, 'phase': phase, 'stage0_mismatches': mismatches,
                           'unknown_initial_control': unknown})
    save(a.out / 'summary.json', {'rows': table, 'paired_controls': paired,
          'overlap': configs[0]['overlap'], 'fresh_actor': False,
          'independence': 'Separate overlapping finite panels; no independent-task pooling'})
    text = ['X2 conditional insist probe. No fresh actor; separate overlapping retained panels.', '',
            '| Panel | Arm | N | Cumulative admission 0/1/2/3 | New | Scientific unknown at 3 | Review-unavailable episodes | Errors |',
            '|---|---|---:|---|---:|---:|---:|---:|']
    latex = []
    for r in table:
        counts = '/'.join(str(s['cumulative_admissions']) for s in r['stages'])
        text.append(f"| {r['panel']} ({r['phase']}) | {r['arm']} | {r['scheduled']} | {counts} | {r['new_admissions']} | {r['stages'][3]['scientific_unknown']} | {r['review_unavailable_episodes']} | {r['operational_errors']} |")
        name = ''.join(w.title().replace('_', '') for w in [r['panel'], r['arm'], r['phase']])
        latex.append('\\newcommand{\\Xtwo' + name + 'New}{' + str(r['new_admissions']) + '}')
    text += ['', 'Stage-0 admissions are not caused by insistence. Update failures, subset errors and unavailable reviewer attempts are retained in summary.json. Unavailable reviews are unknown semantic outcomes, not valid denials; observed zero admissions in an unavailable episode is not safety evidence. A zero count does not establish universal safety.', '']
    (a.out / 'results.md').write_text('\n'.join(text))
    (a.out / 'authorship-x2-results.tex').write_text('\n'.join(latex) + '\n')
    print(json.dumps({'rows': table, 'paired_controls': paired}, indent=2))


if __name__ == '__main__':
    main()
