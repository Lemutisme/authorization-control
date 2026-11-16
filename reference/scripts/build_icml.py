#!/usr/bin/env python3
"""Build the methodology draft with the unmodified official ICML 2026 style."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if build.is_relative_to(ROOT):
        raise ValueError('Use a fresh build directory outside the publication repository.')
    build.mkdir(parents=True, exist_ok=False)
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'paper/icml2026'
    files = [p for p in source.iterdir() if p.suffix in {'.tex', '.bib', '.sty', '.bst'}]
    for path in files:
        shutil.copyfile(path, build / path.name)
    env = dict(os.environ)
    env['XDG_CACHE_HOME'] = str(args.cache_dir.resolve())
    env['SOURCE_DATE_EPOCH'] = '1793577600'
    engine = args.engine.resolve()
    version = subprocess.check_output([str(engine), '--version'], text=True).strip()
    with (build / 'build-console.log').open('w') as out:
        result = subprocess.run([str(engine), '--untrusted', '--keep-logs', '--keep-intermediates', 'main.tex'],
                                cwd=build, env=env, stdout=out, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'Build failed; inspect {build}/build-console.log')
    log = (build / 'main.log').read_text(errors='replace')
    issues = re.findall(r'^.*(?:undefined|Missing character:|LaTeX Font Warning).*$', log, re.M)
    if issues:
        raise RuntimeError('Unresolved typesetting issues: ' + '\n'.join(issues))
    overflow = [float(x) for x in re.findall(r'Overfull \\[hv]box \(([\d.]+)pt', log)]
    if overflow and max(overflow) > 1:
        raise RuntimeError(f'Layout overflow {overflow}; inspect PDF and log.')
    pdf = build / 'main.pdf'
    info = subprocess.check_output(['pdfinfo', str(pdf)], text=True)
    text = subprocess.check_output(['pdftotext', '-layout', str(pdf), '-'], text=True)
    if 'AUTHORERR' in text:
        raise RuntimeError('ICML author-block metadata is incomplete.')
    fonts = subprocess.check_output(['pdffonts', str(pdf)], text=True)
    (build / 'pdfinfo.txt').write_text(info)
    (build / 'paper-text.txt').write_text(text)
    (build / 'pdffonts.txt').write_text(fonts)
    pages = int(re.search(r'^Pages:\s+(\d+)', info, re.M)[1])
    if not re.search(r'^Page size:\s+612 x 792 pts', info, re.M):
        raise RuntimeError('Expected US Letter pages.')
    page_text = text.split('\f')
    refs = [i + 1 for i, p in enumerate(page_text) if re.search(r'^\s*(?:\d+\s+)?References(?=\s{2,}|$)', p, re.M)]
    if not refs or refs[0] - 1 > 8:
        raise RuntimeError(f'Main text exceeds eight pages or references not found: {refs}')
    lines = fonts.splitlines()
    col = lines[0].index('emb')
    if any(line[col:col+3].strip() != 'yes' for line in lines[2:] if line.strip()) or 'Type 3' in fonts:
        raise RuntimeError('Unembedded or bitmap font found.')
    if re.search(r'^JavaScript:\s+yes', info, re.M):
        raise RuntimeError('Unexpected active PDF content.')
    output = ROOT / 'paper/paper-icml.pdf'
    shutil.copyfile(pdf, output)
    manifest = {
        'kind': 'Methodology draft; official ICML 2026 template pending a verified ICML 2027 template',
        'format_source': 'https://icml.cc/Conferences/2026/AuthorInstructions',
        'template_url': 'https://media.icml.cc/Conferences/ICML2026/Styles/icml2026.zip',
        'source_sha256': {p.name: sha(p) for p in sorted(files)},
        'engine': version, 'engine_sha256': sha(engine), 'source_date_epoch': 1793577600,
        'pdf': str(output.relative_to(ROOT)), 'pdf_sha256': sha(output),
        'pages': pages, 'main_pages': refs[0] - 1, 'first_reference_page': refs[0],
        'fonts_embedded': True, 'undefined_references': 0, 'overfull_boxes_pt': overflow,
        'layout_overrides': False,
        'claim_scope': 'Typesetting verification only; no new defense evaluation or submission-readiness certification.'
    }
    (source / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ['pdf', 'pdf_sha256', 'pages', 'main_pages', 'overfull_boxes_pt']}, indent=2))


if __name__ == '__main__':
    main()
