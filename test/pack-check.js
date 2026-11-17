/** Validate the actual distribution from a clean consumer directory. */
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('..', import.meta.url));
const temporary = await mkdtemp(join(tmpdir(), 'authorization-pack-'));
try {
  const [pack] = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', temporary], { cwd: root, encoding: 'utf8' }));
  const allowed = /^(?:package\.json|README\.md|LICENSE|THIRD_PARTY_NOTICES\.md|CHANGELOG\.md|(?:src|extensions|bin|artifact|examples|docs)\/)/;
  for (const file of pack.files) {
    assert.ok(allowed.test(file.path), `Unexpected packed file: ${file.path}`);
    assert.ok(!/(?:^|\/)(?:node_modules|evidence|qualification|\.env|\.git|__pycache__)(?:\/|$)/.test(file.path), `Private/generated material: ${file.path}`);
  }
  const consumer = join(temporary, 'consumer'); await mkdir(consumer);
  await writeFile(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  execFileSync('npm', ['install', join(temporary, pack.filename), '--ignore-scripts', '--omit=dev', '--legacy-peer-deps', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'pipe' });
  const installed = join(consumer, 'node_modules', 'pi-authorization-control');
  for (const file of pack.files.filter(x => /\.(?:js|py|json|md|txt)$/.test(x.path))) {
    const text = await readFile(join(installed, file.path), 'utf8');
    assert.ok(!/\/(?:data|root|home)\//.test(text), `Host path in ${file.path}`);
  }
  const script = `import {AuthorizationController} from 'pi-authorization-control';
import {guardTool} from 'pi-authorization-control/pi-agent';
import extension from 'pi-authorization-control/extension';
import {summarizeMatched} from 'pi-authorization-control/artifact';
const c=new AuthorizationController({policy:{version:1,id:'fresh',rules:[]}});
if(c.begin({toolCallId:'x',toolName:'anything',input:{}}).allowed)throw Error('default deny failed');
if([guardTool,extension,summarizeMatched].some(x=>typeof x!=='function'))throw Error('export missing');
console.log('clean consumer passed');`;
  execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: consumer, stdio: 'pipe' });
  const help = execFileSync(process.execPath, [join(installed, 'bin/artifact.js'), '--help'], { cwd: consumer, encoding: 'utf8' });
  assert.match(help, /summarize/);
  const manifest = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
  assert.equal(manifest.license, 'MIT');
  assert.deepEqual(manifest.pi.extensions, ['./extensions/authorization.js']);
  console.log(JSON.stringify({ passed: true, files: pack.files.length, packedBytes: pack.size, unpackedBytes: pack.unpackedSize, integrity: pack.integrity, cleanConsumer: true }, null, 2));
} finally { await rm(temporary, { recursive: true, force: true }); }
