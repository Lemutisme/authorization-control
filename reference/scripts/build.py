#!/usr/bin/env python3
"""Build offline reading copies from the repository's curated Markdown only."""
from pathlib import Path
import base64
import hashlib
import html
import importlib.metadata
import json
import re
from urllib.parse import urlsplit
from markdown_it import MarkdownIt

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'preview'
DOCS={
    'paper':ROOT/'paper/manuscript.zh-CN.md',
    'motivation':ROOT/'MOTIVATION.md',
    'defense':ROOT/'docs/defense.zh-CN.md',
    'study-protocol':ROOT/'docs/study-protocol.zh-CN.md',
    'safecontract':ROOT/'docs/safecontract-product.md',
    'procontract-fit':ROOT/'docs/procontract-security-fit.md',
    'novelty':ROOT/'docs/safecontract-novelty.md',
    'first-principles':ROOT/'docs/first-principles.md',
    'benchmarks':ROOT/'docs/benchmark-selection.md',
    'experiment-setup':ROOT/'docs/experiment-setup.md',
    'pga-active-evidence':ROOT/'docs/pga-active-evidence.md',
    'pga-method-revision':ROOT/'docs/pga-method-revision.md',
    'zero-regression':ROOT/'docs/zero-regression.md',
    'continuation-theory':ROOT/'docs/continuation-theory.md',
    'novelty-frontier':ROOT/'docs/novelty-frontier.md',
    'contribution-case':ROOT/'docs/contribution-case.md',
    'contract-study':ROOT/'docs/contract-study.md',
    'pga-results':ROOT/'evaluation/PGA.md',
    'paper-motivation':ROOT/'paper/motivation.zh-CN.md',
    'methodology':ROOT/'paper/methodology.zh-CN.md',
    'async-boundary':ROOT/'docs/async-effect-boundary.md',
}
CSS='''body{max-width:1000px;margin:36px auto;padding:0 24px;color:#17212d;background:white;font:17px/1.8 system-ui,-apple-system,"Noto Sans CJK SC","Microsoft YaHei",sans-serif}h1{font-size:30px;line-height:1.35}p{margin:1em 0}strong{color:#102e4c}table{border-collapse:collapse;width:100%;font-size:14px;line-height:1.55;margin:24px 0}th,td{border:1px solid #ced9e4;padding:9px 12px;text-align:left;vertical-align:top}th{background:#edf3f9}pre{overflow:auto;background:#f3f5f7;padding:18px;font-size:13px;line-height:1.55}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em}img{max-width:100%;height:auto}a{color:#155aa0;overflow-wrap:anywhere}li{margin:.45em 0}.notice{font-size:14px;background:#eef4fb;padding:12px 18px;border-left:4px solid #426b95}@media print{@page{size:A4;margin:18mm}body{margin:0;padding:0;font-size:10.5pt;line-height:1.55}h1{font-size:21pt}table{font-size:8.5pt}tr,img{break-inside:avoid}pre{white-space:pre-wrap}a{color:inherit;text-decoration:none}.notice{font-size:9pt}}'''

def rewrite_links(rendered,source):
    def replace(match):
        attr,url=match.group(1),html.unescape(match.group(2))
        if urlsplit(url).scheme or url.startswith('#'):return match.group(0)
        parsed=urlsplit(url)
        target=(source.parent/parsed.path).resolve()
        if not target.is_relative_to(ROOT):raise ValueError('Link leaves repository: '+url)
        if attr=='src' and target.suffix=='.svg':
            return 'src="data:image/svg+xml;base64,'+base64.b64encode(target.read_bytes()).decode()+'"'
        name=next((k for k,p in DOCS.items() if p==target),None)
        rewritten=name+'.html' if name else '../'+target.relative_to(ROOT).as_posix()
        if parsed.fragment:rewritten+='#'+parsed.fragment
        return attr+'="'+html.escape(rewritten,quote=True)+'"'
    return re.sub(r'(href|src)="([^"]+)"',replace,rendered)

def main():
    OUT.mkdir(exist_ok=True)
    parser=MarkdownIt('commonmark',{'html':False}).enable('table')
    manifests=[]
    for name,source in DOCS.items():
        data=source.read_bytes();rendered=rewrite_links(parser.render(data.decode()),source)
        title=source.read_text().splitlines()[0].lstrip('# ')
        page='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'"><title>'+html.escape(title)+'</title><style>'+CSS+'</style></head><body><div class="notice">SP27 · 研究初稿 · 案例事实与未验证设计分开陈述 · 可用浏览器打印为 PDF</div>'+rendered+'</body></html>'
        target=OUT/(name+'.html');target.write_text(page)
        manifests.append({'source':source.relative_to(ROOT).as_posix(),'source_sha256':hashlib.sha256(data).hexdigest(),'output':target.relative_to(ROOT).as_posix(),'output_sha256':hashlib.sha256(page.encode()).hexdigest()})
    (OUT/'manifest.json').write_text(json.dumps({'renderer':'markdown-it-py','version':importlib.metadata.version('markdown-it-py'),'documents':manifests},indent=2)+'\n')
    print('Built '+str(len(manifests))+' offline reading copies.')

if __name__=='__main__':main()
