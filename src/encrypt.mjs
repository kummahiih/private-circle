/**
 * Core encryption logic for private-circle gated static pages.
 * Supports PBKDF2-SHA256 and WebAuthn-PRF enrollment hashes.
 */
export {
  normalizePageId,
  b64,
  xorBuf,
  buildPbkdf2Salt,
  prfSaltForPage,
} from './util.mjs';

export { loadHashes } from './load-hashes.mjs';
export { buildLoader, buildLoaderHtml, buildGateConfig } from './build-loader.mjs';
export { encryptPage } from './encrypt-page.mjs';
