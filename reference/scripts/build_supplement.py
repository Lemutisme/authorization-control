#!/usr/bin/env python3
"""Compile the standalone technical supplement, outside the submission PDF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True)
    p.add_argument('--build-dir',type=Path,required=True);p.add_argument('--cache-dir',type=Path,required=True);a=p.parse_args()
    work=a.build_dir.resolve()
    if work.is_relative_to(ROOT):raise ValueError('Build outside the publication repository.')
    work.mkdir(parents=True,exist_ok=False);hashes={}
    for name in ['supplement.tex','active-evidence-supplement.tex','binding-revision-supplement.tex','provider-semantic-supplement.tex','proactive-supplement.tex','incident-case.tex','intent-guard-supplement.tex','continuation-supplement.tex','novelty-frontier-supplement.tex','contract-study-supplement.tex','fact-screen-supplement.tex','intervention-semantics-supplement.tex','multibench-supplement.tex','explicit-grants-supplement.tex','diagnostic-crossover-supplement.tex','baseline-audit-supplement.tex','multibench-results.tex','references.bib']:
        source=ROOT/'paper/latex'/name;shutil.copyfile(source,work/name)
        hashes['paper/latex/'+name]=hashlib.sha256(source.read_bytes()).hexdigest()
    (work/'technical.tex').write_text('\\RequirePackage[T1]{fontenc}\n\\input{supplement.tex}\n')
    env=dict(os.environ);env.update(XDG_CACHE_HOME=str(a.cache_dir.resolve()),SOURCE_DATE_EPOCH='1793577600')
    engine=a.engine.resolve();print('Building standalone technical supplement...',flush=True)
    with (work/'build-console.log').open('w') as output:
        result=subprocess.run([str(engine),'--untrusted','--keep-logs','--keep-intermediates','technical.tex'],cwd=work,env=env,stdout=output,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError('Supplement TeX failed; inspect retained build log.')
    log=(work/'technical.log').read_text(errors='replace')
    if re.search(r'(Citation|Reference).*undefined|There were undefined references|LaTeX Font Warning|Missing character:',log):raise RuntimeError('Unresolved reference or font substitution.')
    overfull=[float(x) for x in re.findall(r'Overfull \\[hv]box \(([\d.]+)pt',log)]
    if overfull and max(overfull)>1:raise RuntimeError('Supplement layout overflow; inspect PDF.')
    pdf=work/'technical.pdf';info=subprocess.run(['pdfinfo',str(pdf)],capture_output=True,text=True,check=True).stdout
    if 'Document Class: IEEEtran 2015/08/26 V1.8b' not in log or not re.search(r'^Page size:\s+612 x 792 pts',info,re.M):raise RuntimeError('Unexpected class or paper size.')
    fonts=subprocess.run(['pdffonts',str(pdf)],capture_output=True,text=True,check=True).stdout;lines=fonts.splitlines();col=lines[0].index('emb')
    if any(line[col:col+3].strip()!='yes' for line in lines[2:] if line.strip()) or 'Type 3' in fonts:raise RuntimeError('Unembedded/bitmap font.')
    if re.search(r'^JavaScript:\s+yes',info,re.M):raise RuntimeError('Unexpected active PDF content.')
    text=subprocess.run(['pdftotext','-layout',str(pdf),'-'],capture_output=True,text=True,check=True).stdout
    (work/'technical-text.txt').write_text(text);(work/'pdfinfo.txt').write_text(info);(work/'pdffonts.txt').write_text(fonts)
    target=ROOT/'paper/technical-supplement.pdf';shutil.copyfile(pdf,target)
    report={'kind':'Standalone working technical supplement; not automatically part of an S&P submission',
            'class':'IEEEtran 1.8b','class_options':['conference','compsoc'],'paper_size_pt':[612,792],
            'pages':int(re.search(r'^Pages:\s+(\d+)',info,re.M)[1]),
            'source_sha256':hashes,'pdf':'paper/technical-supplement.pdf','pdf_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'all_fonts_embedded':True,'undefined_references':0,'font_substitution_warnings':0,'overfull_boxes_pt':overfull,
            'scope':'Logical proofs are conditional; concrete observation, policy/model adequacy and provider correspondence remain obligations. Only the source listed in theory/verification.json is mechanized.'}
    (ROOT/'paper/latex/supplement-manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'pdf':report['pdf'],'pages':report['pages'],'pdf_sha256':report['pdf_sha256']},indent=2))

if __name__=='__main__':main()
