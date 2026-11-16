#!/usr/bin/env python3
"""Render the curated bibliography and audit distinct, actually cited references.

The catalog records reading scope; this checker does not turn source retrieval
or metadata identity into independent verification of a paper's results.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import unicodedata

ROOT=Path(__file__).resolve().parents[1]
SOURCES=['main.tex', 'intro.tex', 'related.tex', 'prelim.tex', 'method.tex', 'research-questions.tex', 'evidence.tex', 'control-results.tex', 'construction-diagnostic.tex', 'discussion.tex', 'contract-study-results.tex', 'multibench-results.tex', 'control-appendix.tex']

def parse_bib(text):
    entries={}
    for match in re.finditer(r'@(\w+)\s*\{\s*([^,\s]+)\s*,',text):
        start=match.start();pos=text.index('{',start);depth=0
        for end in range(pos,len(text)):
            if end and text[end-1]=='\\':continue
            if text[end]=='{':depth+=1
            elif text[end]=='}':
                depth-=1
                if depth==0:break
        else:raise ValueError('Unclosed BibTeX entry '+match[2])
        if match[2] in entries:raise ValueError('Duplicate cite key '+match[2])
        body=text[match.end():end];fields={}
        for field in re.finditer(r'(\w+)\s*=\s*(\{|"|\d+)',body):
            name=field[1].lower();value=field[2];begin=field.end()
            if value=='{':
                level=1
                for stop in range(begin,len(body)):
                    if stop and body[stop-1]=='\\':continue
                    if body[stop]=='{':level+=1
                    elif body[stop]=='}':
                        level-=1
                        if not level:break
                fields[name]=body[begin:stop]
            elif value=='"':fields[name]=body[begin:body.index('"',begin)]
            else:fields[name]=value
        entries[match[2]]={'key':match[2],'type':match[1].lower(),'fields':fields,'bibtex':text[start:end+1]}
    return entries

def normalize_title(value):
    value=re.sub(r'\\[a-zA-Z]+','',value)
    return re.sub(r'[^a-z0-9]','',unicodedata.normalize('NFKD',value).encode('ascii','ignore').decode().lower())

def latex_safe(text):
    text=text.replace('$τ$',r'$\tau$')
    special={'’':"'",'‘':"'",'“':'``','”':"''",'–':'--','—':'---','\u00a0':' ',
             'ł':r'{\l{}}','Ł':r'{\L{}}','ø':r'{\o{}}','Ø':r'{\O{}}','æ':r'{\ae{}}','Æ':r'{\AE{}}',
             'ß':r'{\ss{}}','τ':r'{$\tau$}'}
    accents={'\u0301':"'",'\u0300':'`','\u0302':'^','\u0303':'~','\u0308':'"','\u030c':'v','\u0304':'=','\u0306':'u','\u030a':'r','\u0327':'c','\u0307':'.','\u030b':'H'}
    output=[]
    for char in text:
        if ord(char)<128:output.append(char)
        elif char in special:output.append(special[char])
        else:
            sequence=unicodedata.normalize('NFD',char)
            if len(sequence)>1 and ord(sequence[0])<128 and all(c in accents for c in sequence[1:]):
                value=sequence[0]
                for accent in sequence[1:]:value='\\'+accents[accent]+'{'+value+'}'
                output.append('{'+value+'}')
            else:raise ValueError('Unmapped bibliography Unicode '+repr(char))
    return ''.join(output)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--render',action='store_true');args=parser.parse_args()
    path=ROOT/'paper/latex/reference-catalog.json';catalog=json.loads(path.read_text());records=catalog['references']
    if args.render:
        bibliography='% Curated distinct works. Reading scopes and source identities: reference-catalog.json.\n\n'
        bibliography+='\n\n'.join(latex_safe(record['bibtex']) for record in records)+'\n'
        (ROOT/'paper/latex/references.bib').write_text(bibliography)
    entries=parse_bib((ROOT/'paper/latex/references.bib').read_text());cited={};errors=[]
    for name in SOURCES:
        source=ROOT/'paper/latex'/name
        for line_number,line in enumerate(source.read_text().splitlines(),1):
            line=re.split(r'(?<!\\)%',line)[0]
            if '\\nocite' in line:errors.append('Uncited bibliography expansion is not allowed.')
            for group in re.findall(r'\\cite(?:\[[^]]*\])*\{([^}]+)\}',line):
                for key in group.split(','):cited.setdefault(key.strip(),[]).append(f'paper/latex/{name}:{line_number}')
    if set(entries)!=set(cited):errors.append({'uncited':sorted(set(entries)-set(cited)),'missing':sorted(set(cited)-set(entries))})
    if len(cited)<80:errors.append('Fewer than80 distinct body-cited references.')
    if set(entries)!={r['key'] for r in records}:errors.append('Catalog/BibTeX key mismatch.')
    seen={};identifiers={}
    for key,entry in entries.items():
        title=normalize_title(entry['fields'].get('title',''))
        if not title:errors.append('Missing title '+key)
        if title in seen:errors.append('Duplicate work title '+seen[title]+'/'+key)
        seen[title]=key
        doi=entry['fields'].get('doi','').lower().strip()
        arxiv=re.search(r'arxiv\.org/(?:abs|pdf)/(\d{4}\.\d{4,5})',entry['fields'].get('url',''))
        for identity in ([('doi',doi)] if doi else [])+([('arxiv',arxiv[1])] if arxiv else []):
            if identity in identifiers:errors.append('Duplicate work identifier '+identifiers[identity]+'/'+key)
            identifiers[identity]=key
    for record in records:
        for field in ['kind','read_level','supported_claim','limitation','sources']:
            if not record.get(field):errors.append(record['key']+': missing '+field)
        if not all(s.get('url') and s.get('sha256') for s in record['sources']):errors.append(record['key']+': incomplete source identity')
    if errors:print(json.dumps(errors,indent=2,ensure_ascii=False));raise SystemExit(1)
    audit={'distinct_references':len(entries),'distinct_body_citations':len(cited),
           'research_works':sum(r['kind']=='research' for r in records),
           'standards_software_or_incident_sources':sum(r['kind']!='research' for r in records),
           'duplicate_titles_or_identifiers':0,'uncited_entries':0,
           'catalog_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
           'bibliography_sha256':hashlib.sha256((ROOT/'paper/latex/references.bib').read_bytes()).hexdigest(),
           'citation_locations':cited,
           'scope':'Primary identity and declared reading-scope audit; not proof/artifact reproduction or global novelty certification.'}
    (ROOT/'evidence/reference-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    print(json.dumps({key:value for key,value in audit.items() if key!='citation_locations'},indent=2))

if __name__=='__main__':main()
