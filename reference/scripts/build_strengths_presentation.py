"""Compile and inspect the six-slide research presentation in an external directory."""
import argparse,datetime,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True);p.add_argument('--build-dir',type=Path,required=True);p.add_argument('--cache-dir',type=Path,required=True);a=p.parse_args()
 work=a.build_dir.resolve();assert not work.is_relative_to(ROOT);work.mkdir(parents=True,exist_ok=False)
 names=['presentation/strengths.tex','presentation/strengths-data.tex'];inputs={}
 for name in names:source=ROOT/name;shutil.copyfile(source,work/source.name);inputs[name]=sha(source)
 (work/'slides.tex').write_text('\\RequirePackage[T1]{fontenc}\n\\input{strengths.tex}\n')
 env=dict(os.environ);env.update(XDG_CACHE_HOME=str(a.cache_dir.resolve()),SOURCE_DATE_EPOCH=str(int(datetime.datetime(2026,11,8,tzinfo=datetime.timezone.utc).timestamp())))
 with (work/'build-console.log').open('w') as f:r=subprocess.run([str(a.engine.resolve()),'--untrusted','--keep-logs','--keep-intermediates','slides.tex'],cwd=work,env=env,stdout=f,stderr=subprocess.STDOUT)
 if r.returncode:raise RuntimeError('Presentation build failed; inspect external log')
 log=(work/'slides.log').read_text(errors='replace')
 if re.search(r'(Citation|Reference).*undefined|LaTeX Font Warning|Missing character:',log):raise RuntimeError('Presentation reference/font failure')
 overflow=[float(v) for v in re.findall(r'Overfull \\[hv]box \(([\d.]+)pt',log)]
 if overflow and max(overflow)>1:raise RuntimeError('Presentation layout overflow: '+str(overflow))
 pdf=work/'slides.pdf';info=subprocess.check_output(['pdfinfo',str(pdf)],text=True);pages=int(re.search(r'^Pages:\s+(\d+)',info,re.M)[1]);assert pages==6
 fonts=subprocess.check_output(['pdffonts',str(pdf)],text=True);lines=fonts.splitlines();col=lines[0].index('emb');assert all(s[col:col+3].strip()=='yes' for s in lines[2:] if s.strip()) and 'Type 3' not in fonts
 text=subprocess.check_output(['pdftotext','-layout',str(pdf),'-'],text=True);(work/'slides-text.txt').write_text(text);(work/'pdfinfo.txt').write_text(info);(work/'pdffonts.txt').write_text(fonts)
 assert 'JavaScript:      yes' not in info
 target=ROOT/'presentation/strengths.pdf';shutil.copyfile(pdf,target)
 result={'kind':'Six-slide research positioning; not a venue-readiness verdict','pages':pages,'aspect_ratio':'16:9','source_sha256':inputs,'evidence_sha256':sha(ROOT/'evidence/strengths-presentation/checked-evidence.json'),'engine_sha256':sha(a.engine),'pdf':'presentation/strengths.pdf','pdf_sha256':sha(target),'fonts_embedded':True,'overfull_boxes_pt':overflow,'scope':'The PDF presents finite development measurements, implementation scope and an explicitly unmeasured comparative gap.'}
 (ROOT/'presentation/build-manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
