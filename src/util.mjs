/**
 * Shared crypto helpers for private-circle
 */
export function normalizePageId(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, '-');
}

export function b64(buf) {
  return Buffer.from(buf).toString('base64');
}

export function xorBuf(a, b) {
  if (a.length !== b.length) throw new Error('xor length mismatch');
  const o = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i];
  return o;
}

/** PBKDF2 salt = randomSalt || UTF-8(pageId) */
export function buildPbkdf2Salt(randomSalt, pageId) {
  return Buffer.concat([randomSalt, Buffer.from(pageId, 'utf8')]);
}

/** Deterministic PRF salt used by both enroll and loader */
export function prfSaltForPage(pageId) {
  return Buffer.from('circle-prf:v1:' + pageId, 'utf8');
}
