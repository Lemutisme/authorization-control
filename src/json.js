/** Copy JSON data without silent coercion or prototype-property assignment. */
export function copyJson(value, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object' || seen.has(value)) throw new TypeError('Expected acyclic JSON data');
  const proto = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && proto !== Object.prototype && proto !== null) throw new TypeError('Expected plain JSON object');
  if (Object.getOwnPropertySymbols(value).length) throw new TypeError('Symbol properties are not JSON');
  const keys = Object.keys(value);
  if (Array.isArray(value) && (keys.length !== value.length || keys.some((key, i) => key !== String(i)))) throw new TypeError('Sparse or decorated arrays are not JSON');
  seen.add(value);
  const out = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) throw new TypeError('Accessor properties are not JSON');
    Object.defineProperty(out, key, { value: copyJson(descriptor.value, seen), enumerable: true, writable: true, configurable: true });
  }
  seen.delete(value);
  return out;
}

/** Tool results use their JSON representation; optional undefined object fields are omitted. */
export function observationSnapshot(value) {
  return JSON.parse(JSON.stringify(value, (_key, x) => {
    if (['function', 'symbol', 'bigint'].includes(typeof x) || (typeof x === 'number' && !Number.isFinite(x))) throw new TypeError('Non-JSON observation');
    return x;
  }));
}

export function freezeJson(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freezeJson(item);
    Object.freeze(value);
  }
  return value;
}

export function canonicalJson(value) {
  const normalized = copyJson(value);
  const order = x => Array.isArray(x) ? x.map(order) : x && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map(k => [k, order(x[k])])) : x;
  return JSON.stringify(order(normalized));
}
