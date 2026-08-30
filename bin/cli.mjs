#!/usr/bin/env node
/**
 * CLI for @kummahiih/private-circle
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { encryptPage, normalizePageId } from '../src/encrypt.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function usage() {
  console.log(`
Usage:
  private-circle encrypt --page-id <id> --content <file|dir> --hashes <dir> --out <dir>
  private-circle init [--dir <path>]

  --content  single HTML file (v1) or directory of .html/.js/.css (multifile, same K)
  --no-lock-page-id  leave enroll.html pageId field editable (default: lock to --page-id)
`);
}

function parseArgs(argv) {
  const out = {
    command: argv[2] || '',
    content: 'content/index.html',
    hashes: 'hashes',
    outDir: 'dist',
    pageId: '',
    dir: '.',
    lockPageId: true,
  };
  for (let i = 3; i < argv.length; i++) {
    if (argv[i] === '--content') out.content = argv[++i];
    else if (argv[i] === '--hashes') out.hashes = argv[++i];
    else if (argv[i] === '--out') out.outDir = argv[++i];
    else if (argv[i] === '--page-id') out.pageId = argv[++i];
    else if (argv[i] === '--dir') out.dir = argv[++i];
    else if (argv[i] === '--no-lock-page-id') out.lockPageId = false;
  }
  return out;
}

function cmdEncrypt(args) {
  const result = encryptPage({
    pageId: args.pageId,
    content: args.content,
    hashes: args.hashes,
    outDir: args.outDir,
    lockPageId: args.lockPageId,
  });
  console.log('pageId:', result.pageId);
  console.log('Wrote', path.join(args.outDir, 'index.html'));
  console.log('Entries:', result.entries);
  if (result.multifile) {
    console.log('Multifile assets:', result.files);
  }
  if (result.enrollCopied) {
    console.log('Copied enroll page →', path.join(args.outDir, 'enroll.html'),
      result.lockPageId ? '(pageId locked)' : '(pageId editable)');
  } else {
    console.log('Note: no enroll.html found (optional)');
  }
}

function cmdInit(args) {
  const root = path.resolve(args.dir);
  for (const d of ['content', 'hashes']) {
    fs.mkdirSync(path.join(root, d), { recursive: true });
  }

  const require = createRequire(import.meta.url);
  let assetsDir = path.join(__dirname, '..', 'assets');
  try {
    const pkg = require.resolve('@kummahiih/circle-enroll/package.json');
    assetsDir = path.join(path.dirname(pkg), 'assets');
  } catch {}
  for (const name of ['enroll.html', 'enroll.css', 'enroll-core.js', 'enroll-prf.js']) {
    const src = path.join(assetsDir, name);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(root, name));
      console.log('Created', name);
    }
  }

  const contentPath = path.join(root, 'content', 'index-plaintext.html');
  if (!fs.existsSync(contentPath)) {
    fs.writeFileSync(
      contentPath,
      `<!DOCTYPE html>
<html lang="fi">
<head><meta charset="UTF-8"><title>Private circle</title></head>
<body>
  <h1>Tervetuloa</h1>
  <p>Tämä sivu on salattu. Vain rekisteröityneet jäsenet näkevät sisällön.</p>
</body>
</html>
`,
      'utf8'
    );
    console.log('Created content/index-plaintext.html');
  }

  const vercelPath = path.join(root, 'vercel.json');
  if (!fs.existsSync(vercelPath)) {
    fs.writeFileSync(
      vercelPath,
      JSON.stringify(
        {
          buildCommand:
            'npx @kummahiih/private-circle encrypt --page-id YOUR-PAGE-ID --content content/index-plaintext.html --hashes hashes --out dist',
          outputDirectory: 'dist',
          cleanUrls: true,
        },
        null,
        2
      ) + '\n',
      'utf8'
    );
    console.log('Created vercel.json (edit YOUR-PAGE-ID)');
  }

  console.log('\nNext steps:');
  console.log('  1. Edit content/index-plaintext.html');
  console.log('  2. Collect enroll JSON files into hashes/');
  console.log('  3. Set pageId in vercel.json');
  console.log('  4. Deploy');
}

const args = parseArgs(process.argv);

if (args.command === 'encrypt') {
  if (!args.pageId) {
    console.error('Missing --page-id');
    usage();
    process.exit(1);
  }
  try {
    cmdEncrypt(args);
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
} else if (args.command === 'init') {
  cmdInit(args);
} else {
  usage();
  process.exit(args.command ? 1 : 0);
}
