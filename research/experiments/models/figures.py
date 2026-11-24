"""Plot completed finite-panel contrasts; no population-confidence claim."""
import argparse,json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--analysis',default='analysis/result.json');p.add_argument('--out',default='figures');a=p.parse_args()
    result=json.loads((HERE/a.analysis).read_text());models=result['included_models']
    labels={'luna':'Luna','haiku':'Haiku 5.5','deepseek':'DeepSeek V4.1 Flash'}
    panels=[('corruption','Wrong binding → wrong effect',20),('correction','Correct binding → correction',10),
            ('permission','Refused harmful proposal → permission',2),('honest_fault_permission','Correct proposal → permission',None)]
    fig,axes=plt.subplots(2,2,figsize=(10.4,6.5),layout='constrained')
    for ax,(suffix,title,threshold) in zip(axes.flat,panels):
        for i,model in enumerate(models):
            c=result['contrasts'][model+'_'+suffix]
            lower,upper=100*c['lower'],100*c['upper'];mid=(lower+upper)/2
            ax.plot([lower,upper],[i,i],color='#0072B2',linewidth=5,solid_capstyle='round')
            ax.scatter([mid],[i],s=45,color='#0072B2',zorder=3)
            desc=c.get('descriptive_task_bootstrap95')
            if desc:
                ax.plot([100*desc[0],100*desc[1]],[i,i],color='#777777',linewidth=1.6,zorder=1)
            text=f'{mid:+.1f}' if lower==upper else f'[{lower:+.1f}, {upper:+.1f}]'
            ax.annotate(text,(upper,i),xytext=(7,0),textcoords='offset points',va='center',fontsize=9)
        ax.axvline(0,color='#555555',linewidth=.8)
        if threshold is not None:ax.axvline(threshold,color='#D55E00',linestyle=':',linewidth=1,label='Forecast threshold')
        ax.set_yticks(range(len(models)),[labels[m] for m in models]);ax.invert_yaxis()
        ax.set_title(title,fontsize=10.5);ax.set_xlabel('Task-macro paired change (percentage points)')
        ax.grid(axis='x',alpha=.16);ax.margins(x=.25,y=.3)
        ax.spines[['top','right']].set_visible(False)
    fig.suptitle('Authorization feedback and update effects across model families',fontsize=13)
    fig.supxlabel('Blue: finite-panel estimate / missing-outcome bounds. Gray: descriptive task bootstrap where fully observed.\nInspected task clusters; no population prevalence or population confidence claim.',fontsize=8)
    out=HERE/a.out;out.mkdir(parents=True,exist_ok=True)
    fig.savefig(out/'cross-model-effects.png',dpi=220);fig.savefig(out/'cross-model-effects.pdf')
    (out/'plot-provenance.json').write_text(json.dumps({'source':a.analysis,'matplotlib':matplotlib.__version__,'observed':result['observed'],'scheduled':result['scheduled']},indent=2)+'\n')
if __name__=='__main__':main()
