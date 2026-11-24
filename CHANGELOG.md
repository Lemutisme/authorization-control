# Changelog

## 0.2.0

- Group the paper's pinned material under `research/`: `experiments/`, `inputs/`, `data/` and the native replay script (`replay/`, formerly `artifact/`). The pinned files are unchanged byte for byte, and the workspace that experiments run in keeps its layout.
- Keep the runtime tests in `test/` and move the pipeline tests to `pipeline/tests/`.
- Define the research locations once in `pipeline/paths.py` and format the pipeline code; its behaviour is unchanged.
- Add `scripts/build_manifest.py` (`npm run manifest`) to rewrite `MANIFEST.json` from the tracked files.
- Name the accompanying paper by its preprint title and record the author and repository in `package.json`.

## 0.1.0

- Package the authorization runtime, Pi extension and SDK adapter together.
- Add the full experiment preparation, launch, native replay, analysis and figure pipeline.
- Include complete recorded study data and pinned input protocols.
- Make frozen-prefix replay portable across provider credentials while retaining exact payload/response checks.
- Provide Python 3.13 setup, a pinned container and a short runnable README.
