#!/usr/bin/env python3
"""Render completed, audited same-revision main and repeated clean outcomes."""
import argparse,json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--summary',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--main-run',default='intent-full-paired-main-v16');p.add_argument('--repeat-run',default='intent-clean-repeat-main-v16');a=p.parse_args()
    data=json.loads(a.summary.read_text());runs={r['job']:r for r in data['runs']}
    first=runs[a.repeat_run];full=runs[a.main_run]
    if not first['complete'] or not full['complete']:raise ValueError('Final table requires completed frozen campaigns')
    if first['executed_source_group_sha256']!=full['executed_source_group_sha256']:raise ValueError('Repeated result uses a different executed revision')
    c1=first['conditions']['clean'];c2=full['conditions']['clean'];attack=full['conditions']['attack'];control=full['conditions']['goal_control']
    if (c1['n'],c2['n'],attack['n'],control['n'])!=(97,97,949,35):raise ValueError('Unexpected target scope')
    values={'intentCleanOneNone':f"{c1['baseline_utility']}/97",'intentCleanOneGuard':f"{c1['guard_utility']}/97",
        'intentCleanOneLoss':c1['paired_losses'],'intentCleanTwoNone':f"{c2['baseline_utility']}/97",'intentCleanTwoGuard':f"{c2['guard_utility']}/97",
        'intentCleanTwoLoss':c2['paired_losses'],'intentAttackNone':f"{attack['baseline_utility']}/949",'intentAttackGuard':f"{attack['guard_utility']}/949",
        'intentAttackLoss':attack['paired_losses'],'intentASRNone':f"{attack['baseline_asr']}/949",'intentASRGuard':f"{attack['guard_asr']}/949",
        'intentASRUnknown':attack['asr_unknown'],'intentCleanUnknown':c1['unknown_comparisons']+c2['unknown_comparisons']}
    lines=['% Generated from completed audited '+a.main_run+' and '+a.repeat_run+'; source-read development.']
    lines += ['\\newcommand{\\'+name+'}{'+str(value)+'}' for name,value in values.items()]
    lines+=['\\newcommand{\\intentResultsTable}{%',r'\begin{table}[t]',r'\centering\footnotesize',
        r'\caption{Frozen generic guard with exact-response pairing and two predeclared clean samples, one within the full campaign. Losses and gains are paired, not differences of marginals; goal controls measure separate capability.}',
        r'\label{tab:intent-results}',r'\begin{tabular}{@{}lrrrr@{}}',r'\toprule',r'Stratum & No gate & Guard & Loss & Gain \\',r'\midrule']
    for label,c in [('Clean 1',c1),('Clean 2',c2),('Attacked',attack),('Goal controls',control)]:
        loss=c.get('capability_losses',c['paired_losses']);gain=c.get('capability_gains',c['paired_gains'])
        lines.append(f"{label} & {c['baseline_utility']}/{c['n']} & {c['guard_utility']}/{c['n']} & {loss} & {gain}"+r' \\')
    lines += [r'\bottomrule',r'\end{tabular}',r'\end{table}}']
    direct=runs.get('intent-full-comparison-main-v15--direct');scoped=runs.get('intent-full-comparison-main-v15--owner-scope')
    if direct and scoped:
        dc,sc=direct['conditions'],scoped['conditions']
        values={'intentScopeDirectCleanLoss':dc['clean']['paired_losses'],'intentScopeOwnerCleanLoss':sc['clean']['paired_losses'],
            'intentScopeDirectAttackLoss':dc['attack']['paired_losses'],'intentScopeOwnerAttackLoss':sc['attack']['paired_losses'],
            'intentScopeDirectCalls':direct['arms']['intent_guard']['usage']['guard_calls'],'intentScopeOwnerCalls':scoped['arms']['intent_guard']['usage']['guard_calls']}
        lines += ['\\newcommand{\\'+name+'}{'+str(value)+'}' for name,value in values.items()]
    a.out.write_text('\n'.join(lines)+'\n')
if __name__=='__main__':main()
