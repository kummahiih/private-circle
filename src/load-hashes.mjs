/**
 * Load enrollment hash JSON files
 */
import fs from 'fs';
import path from 'path';
import { normalizePageId, b64 } from './util.mjs';

const MIN_PBKDF2_ITERATIONS = 310000;

/**
 * Load and validate enrollment JSON files for a given pageId.
 * Supports alg: "PBKDF2-SHA256" and "WebAuthn-PRF".
 */
export function loadHashes(dir, pageId) {
  if (!fs.existsSync(dir)) throw new Error('hashes dir missing: ' + dir);
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  if (!files.length) throw new Error('no .json enroll files in ' + dir);
  const list = [];
  for (const f of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    if (raw.v !== 1 || !raw.hash) {
      throw new Error('invalid enroll file (missing v or hash): ' + f);
    }
    const alg = raw.alg || 'PBKDF2-SHA256';
    if (alg !== 'PBKDF2-SHA256' && alg !== 'WebAuthn-PRF') {
      throw new Error('unsupported alg in ' + f + ': ' + alg);
    }
    if (alg === 'PBKDF2-SHA256' && !raw.salt) {
      throw new Error('PBKDF2 enroll missing salt: ' + f);
    }
    const filePage = normalizePageId(raw.pageId || '');
    if (!filePage) {
      throw new Error('missing pageId in enroll file: ' + f + ' (re-enroll with pageId)');
    }
    if (filePage !== pageId) {
      console.warn('skip (pageId mismatch):', f, 'has', filePage, 'expected', pageId);
      continue;
    }
    if (alg === 'PBKDF2-SHA256' && (raw.iterations || 0) < MIN_PBKDF2_ITERATIONS) {
      throw new Error(
        `PBKDF2 iterations too weak in ${f}: ${raw.iterations || 0} < ${MIN_PBKDF2_ITERATIONS}`
      );
    }
    const hashBuf = Buffer.from(raw.hash, 'base64');
    if (hashBuf.length !== 32) {
      throw new Error('hash must be 32 bytes: ' + f);
    }
    list.push({
      file: f,
      alg,
      salt: alg === 'PBKDF2-SHA256' ? Buffer.from(raw.salt, 'base64') : null,
      hash: hashBuf,
      label: raw.label || f,
      pageId: filePage
    });
  }
  if (!list.length) {
    throw new Error('no enroll files matched pageId=' + pageId);
  }
  return list;
}
