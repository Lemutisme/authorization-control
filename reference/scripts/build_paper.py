#!/usr/bin/env python3
"""Build and inspect the academic-English IEEE S&P draft with local Tectonic.

Build inputs/logs stay in a fresh external directory. Only the checked PDF and a
path-free source/build manifest are copied into the publication repository.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
FILES=['main.tex', 'intro.tex', 'related.tex', 'prelim.tex', 'method.tex', 'research-questions.tex', 'evidence.tex', 'control-results.tex', 'refinement-results.tex', 'construction-diagnostic.tex', 'discussion.tex', 'contract-study-results.tex', 'multibench-results.tex', 'references.bib', 'reference-catalog.json', 'control-appendix.tex']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--build-dir',type=Path,required=True);parser.add_argument('--cache-dir',type=Path,required=True)
    args=parser.parse_args();build=args.build_dir.resolve();engine=args.engine.resolve()
    subprocess.run(['python3','-B',str(ROOT/'scripts/audit_references.py')],cwd=ROOT,check=True)
    if build.is_relative_to(ROOT):raise ValueError('Use a build directory outside the publication repository.')
    build.mkdir(parents=True,exist_ok=False);args.cache_dir.mkdir(parents=True,exist_ok=True)
    sources={}
    for name in FILES:
        source=ROOT/'paper/latex'/name;shutil.copyfile(source,build/name)
        sources['paper/latex/'+name]=sha(source)
    # IEEEtran selects its own Times/Helvetica families. Tectonic uses XeTeX;
    # select the standard T1 encoding before class initialization to prevent a
    # TU/ptm -> Latin Modern fallback. No class, margin or spacing is modified.
    wrapper='\\RequirePackage[T1]{fontenc}\n\\input{main.tex}\n'
    (build/'paper.tex').write_text(wrapper)
    env=dict(os.environ);env['XDG_CACHE_HOME']=str(args.cache_dir.resolve())
    epoch=int(datetime.datetime(2026,11,2,tzinfo=datetime.timezone.utc).timestamp())
    env['SOURCE_DATE_EPOCH']=str(epoch)
    version=subprocess.run([str(engine),'--version'],env=env,capture_output=True,text=True,check=True).stdout.strip()
    print('Building academic-English IEEE compsoc paper...',flush=True)
    with (build/'build-console.log').open('w') as log:
        result=subprocess.run([str(engine),'--untrusted','--keep-logs','--keep-intermediates','paper.tex'],
                              cwd=build,env=env,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError('TeX build failed; inspect build-console.log in the selected build directory.')
    log=(build/'paper.log').read_text(errors='replace')
    if 'Document Class: IEEEtran 2015/08/26 V1.8b' not in log:raise RuntimeError('Required IEEEtran 1.8b was not loaded.')
    if re.search(r'(Citation|Reference).*undefined|There were undefined references|LaTeX Font Warning|Missing character:',log):
        raise RuntimeError('Unresolved references or font substitution; inspect paper.log.')
    overfull=[float(x) for x in re.findall(r'Overfull \\[hv]box \(([\d.]+)pt',log)]
    if overfull and max(overfull)>1:raise RuntimeError('Layout overflow larger than 1 pt; inspect paper.log and PDF before publishing.')
    pdf=build/'paper.pdf'
    info=subprocess.run(['pdfinfo',str(pdf)],capture_output=True,text=True,check=True).stdout
    (build/'pdfinfo.txt').write_text(info)
    pages=int(re.search(r'^Pages:\s+(\d+)',info,re.M)[1])
    if not re.search(r'^Page size:\s+612 x 792 pts',info,re.M):raise RuntimeError('PDF is not US Letter.')
    if pages>18:raise RuntimeError('PDF exceeds the conference total-page limit.')
    if re.search(r'^JavaScript:\s+yes',info,re.M):raise RuntimeError('Unexpected active PDF content.')
    extracted=subprocess.run(['pdftotext','-layout',str(pdf),'-'],capture_output=True,text=True,check=True).stdout
    (build/'paper-text.txt').write_text(extracted)
    sections=extracted.split('\f')
    reference_pages=[i+1 for i,text in enumerate(sections) if re.search(r'^\s*References(?=\s{2,}|$)',text,re.M|re.I)]
    if not reference_pages:raise RuntimeError('Could not locate the reference section.')
    first_reference=reference_pages[0]
    # main.tex explicitly starts references on a fresh page, making the
    # main/reference allocations independently checkable without font changes.
    main_pages=first_reference-1
    if main_pages>13:raise RuntimeError('Main-text page bound requires manual review/reduction.')
    appendix_starts=[i+1 for i,text in enumerate(sections) if re.search(r'^\s*Appendix [A-Z]\.',text,re.M)]
    first_appendix=min(appendix_starts) if appendix_starts else None
    reference_pages=(first_appendix if first_appendix is not None else pages+1)-first_reference
    appendix_pages=pages-first_appendix+1 if first_appendix is not None else 0
    if pages-first_reference+1>5:raise RuntimeError('Reference/appendix allocation exceeds five pages.')
    fonts=subprocess.run(['pdffonts',str(pdf)],capture_output=True,text=True,check=True).stdout
    (build/'pdffonts.txt').write_text(fonts)
    lines=fonts.splitlines();column=lines[0].index('emb')
    if any(line[column:column+3].strip()!='yes' for line in lines[2:] if line.strip()):raise RuntimeError('PDF has an unembedded font.')
    if 'Type 3' in fonts:raise RuntimeError('Unexpected bitmap Type 3 font.')
    bibliography=(build/'paper.bbl').read_text()
    bibitems=re.findall(r'\\bibitem(?:\[[^]]*\])?\{([^}]+)\}',bibliography)
    if len(bibitems)<80 or len(bibitems)!=len(set(bibitems)):raise RuntimeError('Printed bibliography has fewer than80 distinct works or duplicate items.')
    output=ROOT/'paper/paper-en.pdf';shutil.copyfile(pdf,output)
    manifest={'kind':'English IEEE S&P-format research draft; not submission-readiness certification',
              'format_source':'https://sp2027.ieee-security.org/cfpapers.html',
              'class':'IEEEtran 1.8b','class_options':['conference','compsoc'],'paper_size_pt':[612,792],
              'engine':version,'engine_sha256':sha(engine),'source_date_epoch':epoch,
              'font_setup':'T1 encoding before IEEEtran for Tectonic/XeTeX; class-selected families retained; no layout overrides.',
              'wrapper_sha256':hashlib.sha256(wrapper.encode()).hexdigest(),'source_sha256':sources,
              'pdf':'paper/paper-en.pdf','pdf_sha256':sha(output),'pages':pages,
              'first_reference_page':first_reference,'main_text_pages':main_pages,'reference_pages':reference_pages,
              'first_appendix_page':first_appendix,'appendix_pages':appendix_pages,'references_and_appendices_pages':pages-first_reference+1,
              'printed_references':len(bibitems),'all_fonts_embedded':True,'font_substitution_warnings':0,
              'undefined_references':0,'overfull_boxes_pt':overfull,
              'remaining_review':'Author/content responsibility, full anonymization and production-defense evidence remain outside this format/build check.'}
    (ROOT/'paper/latex/build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'pdf':manifest['pdf'],'pages':pages,'main_text_pages':main_pages,'reference_pages':manifest['reference_pages'],'appendix_pages':appendix_pages,'references':len(bibitems),
                      'fonts':'embedded; no substitution warnings','citation_status':'resolved','pdf_sha256':manifest['pdf_sha256']},indent=2))

if __name__=='__main__':main()
