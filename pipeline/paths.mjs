import { resolve as joinPath, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = joinPath(dirname(fileURLToPath(import.meta.url)), '..');
export function resolve(resource) {
  if (resource === 'python') return process.env.AC_PYTHON || 'python3';
  return joinPath(process.env.AC_WORKSPACE || joinPath(root, '.work'), resource.replace(/^repo:\/\//, ''));
}
