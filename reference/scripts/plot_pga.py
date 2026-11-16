#!/usr/bin/env python3
"""Standalone descriptive plot of the exploratory native-task utility counts."""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

p=argparse.ArgumentParser();p.add_argument('--summary',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
d=json.loads(a.summary.read_text())
if d['observed']!=d['scheduled']:raise ValueError('Only plot the complete frozen cohort')
tasks=['user_task_6','user_task_7','user_task_32']
rows=d['arms'];matrix=np.array([[r['by_task'][t]['utility']['true']/r['by_task'][t]['n'] for t in tasks] for r in rows])
fig,ax=plt.subplots(figsize=(8.7,4.6),layout='constrained')
im=ax.imshow(matrix,vmin=0,vmax=1,cmap='Blues',aspect='auto')
ax.set_yticks(range(len(rows)),[r['label'] for r in rows]);ax.set_xticks(range(3),['Conditional calendar\ncreation (task 6)','Event-reference\nbinding (task 7)','Create and share\nfile (task 32)'])
for i,r in enumerate(rows):
 for j,t in enumerate(tasks):
  x=r['by_task'][t]
  ax.text(j,i,f"{x['utility']['true']}/{x['n']}",ha='center',va='center',color='white' if matrix[i,j]>.55 else '#14212b',fontsize=11)
ax.set_title('Native task utility: successes / scheduled episodes',loc='left',fontsize=13,pad=14)
ax.set_xticks(np.arange(-.5,3,1),minor=True);ax.set_yticks(np.arange(-.5,len(rows),1),minor=True)
ax.grid(which='minor',color='white',linewidth=2);ax.tick_params(which='minor',bottom=False,left=False)
for spine in ax.spines.values():spine.set_visible(False)
bar=fig.colorbar(im,ax=ax,pad=.02,shrink=.85);bar.set_label('Completion fraction')
fig.supxlabel('Each cell: 1 clean + 2 fixed attacks + 2 benign content-removal controls.\nThree source-read development tasks; no held-out or population claim.',fontsize=9)
a.out.parent.mkdir(parents=True,exist_ok=True)
for ext in ['svg','pdf','png']:
 fig.savefig(a.out.with_suffix('.'+ext),dpi=200,metadata={'Creator':'SP27 exploratory analysis'})
plt.close(fig)
