/**
 * Post-encrypt / CI hygiene: dist must not ship hashes/ or obvious plaintext.
 */
import fs from 'fs';
import path from 'path';

const TEXT_EXT = new Set(['.html', '.js', '.css', '.json', '.txt', '.md', '.svg']);

/**
 * @param {string} outDir
 * @param {{ plaintextMarkers?: string[] }} [opts]
 * @throws {Error} on hygiene failure
 */
export function assertDistHygiene(outDir, opts = {}) {
  const markers = opts.plaintextMarkers || [];
  if (!fs.existsSync(outDir)) {
    throw new Error('dist hygiene: outDir missing: ' + outDir);
  }

  const hashesPath = path.join(outDir, 'hashes');
  if (fs.existsSync(hashesPath)) {
    throw new Error(
      'dist hygiene: hashes/ must not be present under outDir (never publish enroll hashes with dist)'
    );
  }

  // Reject enroll-looking JSON at dist root (gate-config is the only expected JSON)
  for (const name of fs.readdirSync(outDir)) {
    const full = path.join(outDir, name);
    if (!fs.statSync(full).isFile()) continue;
    if (name === 'gate-config.json') continue;
    if (name.endsWith('.json')) {
      try {
        const raw = JSON.parse(fs.readFileSync(full, 'utf8'));
        if (raw && typeof raw === 'object' && raw.hash && (raw.v === 1 || raw.alg)) {
          throw new Error(
            'dist hygiene: enroll-like JSON must not ship in dist: ' + name
          );
        }
      } catch (e) {
        if (e.message && e.message.startsWith('dist hygiene:')) throw e;
        // non-JSON or unrelated — ignore parse errors
      }
    }
  }

  if (!markers.length) return;

  function walk(dir) {
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const st = fs.statSync(full);
      if (st.isDirectory()) {
        walk(full);
        continue;
      }
      const ext = path.extname(name).toLowerCase();
      if (!TEXT_EXT.has(ext)) continue;
      const text = fs.readFileSync(full, 'utf8');
      for (const m of markers) {
        if (m && text.includes(m)) {
          throw new Error(
            'dist hygiene: plaintext marker "' +
              m +
              '" found in ' +
              path.relative(outDir, full)
          );
        }
      }
    }
  }
  walk(outDir);
}
