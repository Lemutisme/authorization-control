# Build and release

```sh
npm ci
npm test
npm run check:types
npm run check:pack
npm pack --ignore-scripts --pack-destination dist
```

The npm package contains the runtime, Pi adapters, examples and API documentation. The repository and source archive additionally contain the experiment implementations, complete recorded data and reproduction pipeline. Run `python3 -m pipeline setup` and `.venv/bin/python -m pipeline reproduce --all` before packaging the complete source release.

After adding, moving or editing a tracked file, run `npm run manifest` to rewrite `MANIFEST.json`; the reproduction refuses to start when the files and the manifest differ.

Use a fixed commit for review. Keep `.env`, `.venv`, `.work`, `.deps`, `node_modules`, generated results and fresh experiment output out of source archives. The manifest checks the delivered files; source and relocation manifests record the experiment versions.
