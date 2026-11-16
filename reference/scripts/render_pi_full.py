#!/usr/bin/env python3
"""Generate the completed full-run table and numeric macros from its summary."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--summary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
d=json.loads(a.summary.read_text());arms={x['arm']:x for x in d['arms']}
if not d['all_main_runs_complete'] or set(arms)!={'none','pga'}:raise ValueError('Require both completed main runs')
lines=['% Generated only from completed full-registry results.']
for arm,suffix in [('none','None'),('pga','PGA')]:
 c=arms[arm]['conditions']
 for field,condition,value in [('Clean','clean','native_success'),('Attack','attack','native_success'),('ASR','attack','asr_true'),('Goal','goal_control','native_success')]:
  lines.append('\\newcommand{\\piFull'+field+suffix+'}{'+str(c[condition][value])+'/'+str(c[condition]['observed'])+'}')
 lines.append('\\newcommand{\\piFullUnknown'+suffix+'}{'+str(c['attack']['asr_unknown'])+'}')
 lines.append('\\newcommand{\\piFullASRKnown'+suffix+'}{'+str(c['attack']['asr_true'])+'/'+str(c['attack']['observed']-c['attack']['asr_unknown'])+'}')
 lines.append('\\newcommand{\\piFullASRUpper'+suffix+'}{'+str(c['attack']['asr_true']+c['attack']['asr_unknown'])+'/'+str(c['attack']['observed'])+'}')
lines+=['\\newcommand{\\piFullTable}{%', '\\begin{table}[t]','\\centering\\footnotesize',
 '\\caption{Full registry under one native attack template. Goal controls are separate. Unknown ASR outcomes remain in the scheduled denominator; low ASR with rejected legitimate work is not useful defense.}',
 '\\label{tab:pi-full}','\\begin{tabular}{@{}lrrrr@{}}','\\toprule',
 'Pi arm & Clean utility & Attack utility & ASR & Unknown \\\\', '\\midrule',
 'No gate & \\piFullCleanNone & \\piFullAttackNone & \\piFullASRNone & \\piFullUnknownNone \\\\',
 'Frozen PGA & \\piFullCleanPGA & \\piFullAttackPGA & \\piFullASRPGA & \\piFullUnknownPGA \\\\',
 '\\bottomrule','\\end{tabular}','\\end{table}}']
a.out.write_text('\n'.join(lines)+'\n')
