/**
 * Encrypt page and write dist/
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { normalizePageId, b64, xorBuf } from './util.mjs';
import { loadHashes } from './load-hashes.mjs';
import { buildLoader } from './build-loader.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Encrypt a clear HTML page and write the gated loader (+ optional enroll.html) to outDir.
 *
 * @param {object} opts
 * @param {string} opts.pageId
 * @param {string} opts.content   path to plaintext HTML
 * @param {string} opts.hashes    path to directory of enroll JSON files
 * @param {string} opts.outDir    output directory (usually "dist")
 * @param {string[]} [opts.enrollSearchPaths] extra places to look for enroll.html
 * @returns {{ pageId: string, entries: number, enrollCopied: boolean }}
 */
export function encryptPage(opts) {
  const pageId = normalizePageId(opts.pageId);
  if (!pageId || pageId.length < 2) {
    throw new Error('Required: pageId (e.g. "metsa-piiri")');
  }
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(pageId)) {
    throw new Error('Invalid pageId. Use a-z, 0-9, ".", "_", "-"');
  }

  const clear = fs.readFileSync(opts.content);
  const enrolls = loadHashes(opts.hashes, pageId);

  const K = crypto.randomBytes(32);
  const share1 = crypto.randomBytes(32);
  const share2 = xorBuf(K, share1);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', K, iv);
  const encBody = Buffer.concat([cipher.update(clear), cipher.final()]);
  const tag = cipher.getAuthTag();
  const cipherFull = Buffer.concat([encBody, tag]);

  const entries = enrolls.map((e) => {
    const mask = xorBuf(e.hash, share2);
    const entry = {
      alg: e.alg,
      mask: b64(mask),
      label: e.label
    };
    if (e.alg === 'PBKDF2-SHA256') {
      entry.salt = b64(e.salt);
    }
    return entry;
  });

  fs.mkdirSync(opts.outDir, { recursive: true });
  const loader = buildLoader({
    pageId,
    share1B64: b64(share1),
    ivB64: b64(iv),
    cipherB64: b64(cipherFull),
    entries
  });
  fs.writeFileSync(path.join(opts.outDir, 'index.html'), loader, 'utf8');
  fs.writeFileSync(
    path.join(opts.outDir, 'robots.txt'),
    'User-agent: *\nDisallow: /\n',
    'utf8'
  );

  // Copy public enrollment page if present
  const enrollCandidates = [
    ...(opts.enrollSearchPaths || []),
    path.join(process.cwd(), 'enroll.html'),
    path.join(process.cwd(), 'assets', 'enroll.html'),
    path.join(__dirname, '..', 'assets', 'enroll.html'), // package asset
  ];
  let enrollCopied = false;
  for (const src of enrollCandidates) {
    if (fs.existsSync(src) && fs.statSync(src).isFile()) {
      const dest = path.join(opts.outDir, 'enroll.html');
      fs.copyFileSync(src, dest);
      enrollCopied = true;
      break;
    }
  }

  return { pageId, entries: entries.length, enrollCopied };
}
