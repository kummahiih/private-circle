/**
 * Tests for @kummahiih/private-circle
 * Run with: node --test test/
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { createRequire } from 'module';
import {
  normalizePageId,
  xorBuf,
  b64,
  buildPbkdf2Salt,
  prfSaltForPage,
  loadHashes,
  encryptPage,
  assertDistHygiene,
} from '../src/encrypt.mjs';

describe('normalizePageId', () => {
  it('lowercases and replaces spaces', () => {
    assert.equal(normalizePageId('  Hello Circle  '), 'hello-circle');
  });
  it('handles empty', () => {
    assert.equal(normalizePageId(''), '');
    assert.equal(normalizePageId(null), '');
  });
});

describe('xorBuf', () => {
  it('XORs equal-length buffers', () => {
    const a = Buffer.from([0x0f, 0xf0]);
    const b = Buffer.from([0xff, 0x0f]);
    const r = xorBuf(a, b);
    assert.deepEqual(r, Buffer.from([0xf0, 0xff]));
  });
  it('throws on length mismatch', () => {
    assert.throws(() => xorBuf(Buffer.from([1]), Buffer.from([1, 2])));
  });
  it('is its own inverse', () => {
    const a = crypto.randomBytes(32);
    const b = crypto.randomBytes(32);
    const x = xorBuf(a, b);
    assert.deepEqual(xorBuf(x, b), a);
    assert.deepEqual(xorBuf(x, a), b);
  });
});

describe('buildPbkdf2Salt / prfSaltForPage', () => {
  it('concatenates random salt + pageId', () => {
    const salt = Buffer.from('abcd');
    const out = buildPbkdf2Salt(salt, 'test-page');
    assert.equal(out.length, 4 + 'test-page'.length);
    assert.deepEqual(out.subarray(0, 4), salt);
  });
  it('PRF salt is deterministic and page-scoped', () => {
    const a = prfSaltForPage('hello-circle');
    const b = prfSaltForPage('hello-circle');
    const c = prfSaltForPage('other');
    assert.deepEqual(a, b);
    assert.notDeepEqual(a, c);
    assert.ok(a.toString('utf8').startsWith('circle-prf:v1:'));
  });
});

describe('loadHashes', () => {
  let tmp;

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-hashes-'));
  });

  after(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function writeEnroll(name, obj) {
    fs.writeFileSync(path.join(tmp, name), JSON.stringify(obj, null, 2));
  }

  it('loads valid PBKDF2 enroll', () => {
    writeEnroll('alice.json', {
      v: 1,
      pageId: 'demo',
      alg: 'PBKDF2-SHA256',
      iterations: 310000,
      hashBytes: 32,
      salt: b64(crypto.randomBytes(16)),
      hash: b64(crypto.randomBytes(32)),
      label: 'alice',
    });
    const list = loadHashes(tmp, 'demo');
    assert.equal(list.length, 1);
    assert.equal(list[0].alg, 'PBKDF2-SHA256');
    assert.equal(list[0].hash.length, 32);
    assert.ok(list[0].salt);
  });

  it('loads valid WebAuthn-PRF enroll', () => {
    writeEnroll('bob-prf.json', {
      v: 1,
      pageId: 'demo',
      alg: 'WebAuthn-PRF',
      hashBytes: 32,
      hash: b64(crypto.randomBytes(32)),
      label: 'bob',
      rpId: 'example.com',
    });
    const list = loadHashes(tmp, 'demo');
    const prf = list.filter((e) => e.alg === 'WebAuthn-PRF');
    assert.ok(prf.length >= 1);
    assert.equal(prf[0].salt, null);
  });

  it('skips pageId mismatch', () => {
    writeEnroll('wrong.json', {
      v: 1,
      pageId: 'other-page',
      alg: 'PBKDF2-SHA256',
      salt: b64(crypto.randomBytes(16)),
      hash: b64(crypto.randomBytes(32)),
    });
    const list = loadHashes(tmp, 'demo');
    assert.ok(list.every((e) => e.pageId === 'demo'));
  });

  it('rejects unsupported alg', () => {
    const badDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-bad-'));
    fs.writeFileSync(
      path.join(badDir, 'bad.json'),
      JSON.stringify({
        v: 1,
        pageId: 'x',
        alg: 'MD5',
        hash: b64(crypto.randomBytes(32)),
      })
    );
    assert.throws(() => loadHashes(badDir, 'x'), /unsupported alg/);
    fs.rmSync(badDir, { recursive: true, force: true });
  });

  it('rejects missing hash', () => {
    const badDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-bad2-'));
    fs.writeFileSync(
      path.join(badDir, 'nohash.json'),
      JSON.stringify({ v: 1, pageId: 'x', alg: 'PBKDF2-SHA256', salt: 'aa' })
    );
    assert.throws(() => loadHashes(badDir, 'x'), /missing v or hash/);
    fs.rmSync(badDir, { recursive: true, force: true });
  });
});

describe('assertDistHygiene', () => {
  it('fails when hashes/ exists under outDir', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-hyg-'));
    fs.mkdirSync(path.join(dir, 'hashes'));
    assert.throws(() => assertDistHygiene(dir), /hashes\/ must not be present/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('fails on plaintext marker', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-hyg2-'));
    fs.writeFileSync(path.join(dir, 'index.html'), 'hello MARKER-LEAK');
    assert.throws(
      () => assertDistHygiene(dir, { plaintextMarkers: ['MARKER-LEAK'] }),
      /plaintext marker/
    );
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe('encryptPage (integration)', () => {
  let root, outDir, hashesDir, contentFile;

  before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-enc-'));
    outDir = path.join(root, 'dist');
    hashesDir = path.join(root, 'hashes');
    fs.mkdirSync(hashesDir);
    contentFile = path.join(root, 'content.html');
    fs.writeFileSync(contentFile, '<h1>Secret content MARKER-XYZ</h1>');

    fs.writeFileSync(
      path.join(hashesDir, 'user.json'),
      JSON.stringify({
        v: 1,
        pageId: 'test-page',
        alg: 'PBKDF2-SHA256',
        iterations: 310000,
        salt: b64(crypto.randomBytes(16)),
        hash: b64(crypto.randomBytes(32)),
        label: 'user',
      })
    );
  });

  after(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const GATE_CSP =
    "default-src 'none'; base-uri 'none'; form-action 'none'; script-src 'self' blob:; style-src 'self' blob:; connect-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; frame-ancestors 'none'";
  const ENROLL_CSP =
    "default-src 'none'; base-uri 'none'; form-action 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; frame-ancestors 'none'";

  it('writes index.html, robots.txt and does not leak plaintext', () => {
    const result = encryptPage({
      pageId: 'test-page',
      content: contentFile,
      hashes: hashesDir,
      outDir,
    });
    assert.equal(result.pageId, 'test-page');
    assert.equal(result.entries, 1);

    const index = fs.readFileSync(path.join(outDir, 'index.html'), 'utf8');
    assert.ok(index.includes('Kirjaudu'));
    assert.ok(!index.includes('<script>'), 'no inline script (strict CSP)');
    assert.ok(index.includes('gate.js'));
    assert.ok(!index.includes('MARKER-XYZ'), 'plaintext must not appear in loader');

    const cspMatch = index.match(
      /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/
    );
    assert.ok(cspMatch, 'index.html must include CSP meta');
    assert.equal(cspMatch[1], GATE_CSP);

    assert.ok(fs.existsSync(path.join(outDir, 'robots.txt')));
    assert.ok(fs.existsSync(path.join(outDir, 'gate-config.json')));
    assert.ok(fs.existsSync(path.join(outDir, 'gate.js')));
    assert.ok(fs.existsSync(path.join(outDir, 'gate.css')));
    assert.ok(!fs.existsSync(path.join(outDir, 'hashes')));
    const cfg = JSON.parse(fs.readFileSync(path.join(outDir, 'gate-config.json'), 'utf8'));
    assert.equal(cfg.pageId, 'test-page');
    assert.ok(cfg.share1 && cfg.iv && cfg.cipher);
  });

  it('copies enroll.html when present', () => {
    const enrollSrc = path.join(root, 'enroll.html');
    fs.writeFileSync(enrollSrc, '<html><body>enroll</body></html>');
    const result = encryptPage({
      pageId: 'test-page',
      content: contentFile,
      hashes: hashesDir,
      outDir,
      enrollSearchPaths: [enrollSrc],
    });
    assert.equal(result.enrollCopied, true);
    assert.ok(fs.existsSync(path.join(outDir, 'enroll.html')));
  });

  it('copies enroll.css (+ siblings) from package assets and matches CSP meta', () => {
    // Point enrollSearchPaths at real circle-enroll assets
    const require = createRequire(import.meta.url);
    let enrollHtml;
    try {
      const pkgJson = require.resolve('@kummahiih/circle-enroll/package.json');
      enrollHtml = path.join(path.dirname(pkgJson), 'assets', 'enroll.html');
    } catch {
      enrollHtml = path.join(root, '..', 'circle-enroll', 'assets', 'enroll.html');
    }
    assert.ok(fs.existsSync(enrollHtml), 'circle-enroll enroll.html must be resolvable');

    const out2 = path.join(root, 'dist-enroll');
    const result = encryptPage({
      pageId: 'test-page',
      content: contentFile,
      hashes: hashesDir,
      outDir: out2,
      enrollSearchPaths: [enrollHtml],
    });
    assert.equal(result.enrollCopied, true);

    const enrollOut = path.join(out2, 'enroll.html');
    const cssOut = path.join(out2, 'enroll.css');
    const coreOut = path.join(out2, 'enroll-core.js');
    const prfOut = path.join(out2, 'enroll-prf.js');
    assert.ok(fs.existsSync(enrollOut));
    assert.ok(fs.existsSync(cssOut), 'enroll.css must be copied alongside enroll.html');
    assert.ok(fs.existsSync(coreOut));
    assert.ok(fs.existsSync(prfOut));

    // Content fingerprint: copied bytes match source
    const srcDir = path.dirname(enrollHtml);
    assert.deepEqual(
      fs.readFileSync(cssOut),
      fs.readFileSync(path.join(srcDir, 'enroll.css'))
    );

    const enrollHtmlText = fs.readFileSync(enrollOut, 'utf8');
    const enrollCsp = enrollHtmlText.match(
      /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/
    );
    assert.ok(enrollCsp, 'enroll.html must include CSP meta');
    assert.equal(enrollCsp[1], ENROLL_CSP);
    assert.ok(enrollHtmlText.includes('href="enroll.css"'));
    assert.ok(!enrollHtmlText.includes('<script>'), 'enroll has no inline scripts');
  });

  it('rejects invalid pageId', () => {
    assert.throws(
      () =>
        encryptPage({
          pageId: 'Bad Page!',
          content: contentFile,
          hashes: hashesDir,
          outDir,
        }),
      /Invalid pageId/
    );
  });

  it('refuses outDir that already has hashes/', () => {
    const badOut = path.join(root, 'bad-out');
    fs.mkdirSync(path.join(badOut, 'hashes'), { recursive: true });
    assert.throws(
      () =>
        encryptPage({
          pageId: 'test-page',
          content: contentFile,
          hashes: hashesDir,
          outDir: badOut,
        }),
      /already contains hashes/
    );
  });
});
