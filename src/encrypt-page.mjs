/**
 * Encrypt page (file or directory) and write dist/ (strict-CSP friendly: no inline scripts).
 * Same K for all assets; per-file IV. Single-file cipher kept for backward compat.
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { normalizePageId, b64, xorBuf } from './util.mjs';
import { loadHashes } from './load-hashes.mjs';
import { buildLoaderHtml, buildGateConfig } from './build-loader.mjs';
import { assertDistHygiene } from './assert-dist-hygiene.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ASSETS = path.join(__dirname, '..', 'assets');
const require = createRequire(import.meta.url);

const TEXT_EXTS = new Set(['.html', '.js', '.css']);
const IV_RETRY_LIMIT = 8;

function resolveEnrollAssets() {
  try {
    const pkgJson = require.resolve('@kummahiih/circle-enroll/package.json');
    return path.join(path.dirname(pkgJson), 'assets');
  } catch {
    return PACKAGE_ASSETS;
  }
}

/**
 * Collect relative paths of encryptable text assets under root.
 * @param {string} root
 * @returns {string[]}
 */
function listContentAssets(root) {
  const out = [];
  function walk(dir, rel) {
    for (const name of fs.readdirSync(dir)) {
      if (name.startsWith('.')) continue;
      const full = path.join(dir, name);
      const r = rel ? path.join(rel, name) : name;
      const st = fs.statSync(full);
      if (st.isDirectory()) {
        walk(full, r);
        continue;
      }
      if (TEXT_EXTS.has(path.extname(name).toLowerCase())) {
        out.push(r.replace(/\\/g, '/'));
      }
    }
  }
  walk(root, '');
  return out.sort();
}

/**
 * Fresh 12-byte IV that has not been used with this content key.
 * AES-GCM + repeated IV + same K is catastrophic.
 * @param {Set<string>} usedIvs base64 IVs already bound to K
 * @param {string} [label]
 * @returns {Buffer}
 */
function uniqueIv(usedIvs, label) {
  for (let attempt = 0; attempt < IV_RETRY_LIMIT; attempt++) {
    const iv = crypto.randomBytes(12);
    const ivB64 = b64(iv);
    if (usedIvs.has(ivB64)) continue;
    usedIvs.add(ivB64);
    return iv;
  }
  const where = label ? ` for file: ${label}` : '';
  throw new Error(`AES-GCM IV collision detected${where} (same K must never reuse an IV)`);
}

/**
 * AES-256-GCM encrypt buffer with given K and a unique IV.
 * @param {Buffer} K
 * @param {Buffer} plain
 * @param {Set<string>} usedIvs
 * @param {string} [label]
 * @returns {{ iv: Buffer, cipherFull: Buffer }}
 */
function encryptBuf(K, plain, usedIvs, label) {
  const iv = uniqueIv(usedIvs, label);
  const cipher = crypto.createCipheriv('aes-256-gcm', K, iv);
  const encBody = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, cipherFull: Buffer.concat([encBody, tag]) };
}

/**
 * Encrypt clear content (single file or directory of html/js/css) and write gated loader to outDir.
 *
 * --content file  → single-file mode (cipher + iv at top level for compat)
 * --content dir   → multifile: files{} map, same K; refuse plaintext content/* in dist
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

  const contentPath = path.resolve(opts.content);
  if (!fs.existsSync(contentPath)) {
    throw new Error('content path not found: ' + opts.content);
  }

  const isDir = fs.statSync(contentPath).isDirectory();
  const enrolls = loadHashes(opts.hashes, pageId);

  const K = crypto.randomBytes(32);
  const share1 = crypto.randomBytes(32);
  const share2 = xorBuf(K, share1);
  /** @type {Set<string>} */
  const usedIvs = new Set();

  /** @type {Record<string, { iv: string, cipher: string }> } */
  const files = {};
  let primaryCipherB64 = null;
  let primaryIvB64 = null;
  const markers = opts.plaintextMarkers ? [...opts.plaintextMarkers] : [];

  if (isDir) {
    const assets = listContentAssets(contentPath);
    if (!assets.length) {
      throw new Error('content directory has no .html/.js/.css files: ' + opts.content);
    }
    for (const rel of assets) {
      const plain = fs.readFileSync(path.join(contentPath, rel));
      const { iv, cipherFull } = encryptBuf(K, plain, usedIvs, rel);
      files[rel] = { iv: b64(iv), cipher: b64(cipherFull) };
      if (!markers.length) {
        const m = plain.toString('utf8').match(/MARKER-[A-Z0-9-]+/);
        if (m) markers.push(m[0]);
      }
    }
    // Prefer index.html as primary for single-field compat if present
    const primaryKey =
      files['index.html'] ? 'index.html' :
      files['index-plaintext.html'] ? 'index-plaintext.html' :
      Object.keys(files).find((k) => k.endsWith('.html')) || Object.keys(files)[0];
    primaryIvB64 = files[primaryKey].iv;
    primaryCipherB64 = files[primaryKey].cipher;
  } else {
    const clear = fs.readFileSync(contentPath);
    const { iv, cipherFull } = encryptBuf(K, clear, usedIvs, path.basename(contentPath));
    primaryIvB64 = b64(iv);
    primaryCipherB64 = b64(cipherFull);
    const base = path.basename(contentPath);
    files[base] = { iv: primaryIvB64, cipher: primaryCipherB64 };
    if (!markers.length) {
      const m = clear.toString('utf8').match(/MARKER-[A-Z0-9-]+/);
      if (m) markers.push(m[0]);
    }
  }

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

  // Refuse if operator accidentally pointed outDir at a tree that already has hashes/
  const existingHashes = path.join(opts.outDir, 'hashes');
  if (fs.existsSync(existingHashes)) {
    throw new Error(
      'outDir already contains hashes/ — refuse to write public dist over enroll secrets'
    );
  }

  // Never copy plaintext content into dist
  if (isDir) {
    const leak = path.join(opts.outDir, 'content');
    if (fs.existsSync(leak)) {
      throw new Error('outDir already contains content/ — refuse plaintext leak');
    }
  }

  fs.writeFileSync(path.join(opts.outDir, 'index.html'), buildLoaderHtml(), 'utf8');
  fs.writeFileSync(
    path.join(opts.outDir, 'gate-config.json'),
    JSON.stringify(
      buildGateConfig({
        pageId,
        share1B64: b64(share1),
        ivB64: primaryIvB64,
        cipherB64: primaryCipherB64,
        entries,
        files: isDir ? files : undefined,
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

  assertDistHygiene(opts.outDir, { plaintextMarkers: markers });

  return {
    pageId,
    entries: entries.length,
    enrollCopied,
    files: Object.keys(files).length,
    multifile: isDir,
  };
}
