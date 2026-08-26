/**
 * Encrypt page and write dist/ (strict-CSP friendly: no inline scripts).
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { normalizePageId, b64, xorBuf } from './util.mjs';
import { loadHashes } from './load-hashes.mjs';
import { buildLoaderHtml, buildGateConfig } from './build-loader.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ASSETS = path.join(__dirname, '..', 'assets');
const require = createRequire(import.meta.url);

function resolveEnrollAssets() {
  try {
    const pkgJson = require.resolve('@kummahiih/circle-enroll/package.json');
    return path.join(path.dirname(pkgJson), 'assets');
  } catch {
    return PACKAGE_ASSETS;
  }
}

/**
 * Encrypt a clear HTML page and write the gated loader to outDir.
 *
 * Outputs (CSP-safe):
 *   index.html       — shell only (script-src 'self')
 *   gate.js          — unlock logic
 *   gate.css         — styles
 *   gate-config.json — per-build secrets (fetched by gate.js)
 *   robots.txt
 *   enroll.html + enroll.css + enroll-*.js (optional)
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
      label: e.label,
    };
    if (e.alg === 'PBKDF2-SHA256') {
      entry.salt = b64(e.salt);
    }
    return entry;
  });

  fs.mkdirSync(opts.outDir, { recursive: true });

  fs.writeFileSync(path.join(opts.outDir, 'index.html'), buildLoaderHtml(), 'utf8');
  fs.writeFileSync(
    path.join(opts.outDir, 'gate-config.json'),
    JSON.stringify(
      buildGateConfig({
        pageId,
        share1B64: b64(share1),
        ivB64: b64(iv),
        cipherB64: b64(cipherFull),
        entries,
      })
    ),
    'utf8'
  );
  fs.writeFileSync(
    path.join(opts.outDir, 'robots.txt'),
    'User-agent: *\nDisallow: /\n',
    'utf8'
  );

  for (const name of ['gate.js', 'gate.css']) {
    const src = path.join(PACKAGE_ASSETS, name);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(opts.outDir, name));
    }
  }

  const enrollDir = resolveEnrollAssets();
  const enrollCandidates = [
    ...(opts.enrollSearchPaths || []),
    path.join(process.cwd(), 'enroll.html'),
    path.join(process.cwd(), 'assets', 'enroll.html'),
    path.join(enrollDir, 'enroll.html'),
    path.join(PACKAGE_ASSETS, 'enroll.html'),
  ];
  let enrollCopied = false;
  for (const src of enrollCandidates) {
    if (fs.existsSync(src) && fs.statSync(src).isFile()) {
      fs.copyFileSync(src, path.join(opts.outDir, 'enroll.html'));
      const dir = path.dirname(src);
      for (const extra of ['enroll.css', 'enroll-core.js', 'enroll-prf.js']) {
        const extraSrc = path.join(dir, extra);
        if (fs.existsSync(extraSrc)) {
          fs.copyFileSync(extraSrc, path.join(opts.outDir, extra));
        }
      }
      enrollCopied = true;
      break;
    }
  }

  return { pageId, entries: entries.length, enrollCopied };
}
