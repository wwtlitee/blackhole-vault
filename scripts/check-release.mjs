import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Script } from 'node:vm';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(await readFile(path.join(root, 'release.json'), 'utf8'));
const sha256 = (bytes, encoding = 'hex') => createHash('sha256').update(bytes).digest(encoding);

async function listFiles(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (!prefix && ['.git', 'pdoc'].includes(entry.name)) continue;
    const relative = `${prefix}${entry.name}`;
    assert.ok(!entry.isSymbolicLink(), `Unexpected symbolic link: ${relative}`);
    if (entry.isDirectory()) {
      files.push(...await listFiles(path.join(directory, entry.name), `${relative}/`));
    } else {
      files.push(relative);
    }
  }
  return files.sort();
}

const files = await listFiles(root);
assert.deepEqual(files, [...manifest.files].sort(), 'Publication file allowlist changed');
const buffers = await Promise.all(files.map(file => readFile(path.join(root, file))));
for (let index = 0; index < files.length; index += 1) {
  assert.ok(!buffers[index].subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])), `${files[index]} has a UTF-8 BOM`);
}

const htmlBuffer = buffers[files.indexOf(manifest.entrypoint)];
assert.equal(htmlBuffer.length, manifest.entrypointBytes, 'Application byte size changed');
assert.equal(sha256(htmlBuffer), manifest.entrypointSha256, 'Application SHA-256 changed');
const html = htmlBuffer.toString('utf8').replace(/\r\n?/g, '\n');
assert.ok(html.includes(`name="application-version" content="${manifest.version}"`), 'Application version mismatch');
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
assert.equal(scripts.length, 1, 'Expected one inline application script');
assert.ok(!/\bsrc\s*=/i.test(scripts[0][1]), 'External script dependency');
new Script(scripts[0][2], { filename: manifest.entrypoint });
const scriptHash = sha256(Buffer.from(scripts[0][2]), 'base64');
assert.ok(html.includes(`script-src 'sha256-${scriptHash}'`), 'Inline script CSP hash mismatch');
assert.ok(html.includes("connect-src 'none'"), 'Network-blocking CSP is missing');

const externalReferences = [];
for (const match of html.matchAll(/\b(?:src|href)\s*=\s*(["'])(.*?)\1/gi)) {
  const reference = match[2].trim();
  if (reference && !reference.startsWith('#') && !reference.startsWith('data:')) externalReferences.push(reference);
}
for (const match of html.matchAll(/\burl\(\s*(["']?)(.*?)\1\s*\)/gi)) {
  const reference = match[2].trim();
  if (reference && !reference.startsWith('#') && !reference.startsWith('data:')) externalReferences.push(reference);
}
assert.equal(externalReferences.length, 0, 'External asset reference found');
assert.ok(!/\b(?:fetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon\s*\(|import\s*\()/i.test(scripts[0][2]), 'Network or dynamic module primitive found');

// This is a publication guard, not an exhaustive security audit. Report only
// rule names and line numbers so a failed check never prints a possible secret.
const secretRules = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g],
  ['aws-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g],
  ['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}\b/g],
  ['google-key', /\bAIza[A-Za-z0-9_-]{35}\b/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b/g],
  ['credential-literal', /\b(?:apiKey|secretKey|accessToken|authToken|privateKey|password)\s*[:=]\s*["'][^"'\r\n]{12,}["']/gi],
];
const findings = [];
for (let index = 0; index < files.length; index += 1) {
  const source = buffers[index].toString('utf8');
  for (const [rule, pattern] of secretRules) {
    for (const match of source.matchAll(pattern)) {
      findings.push({ file: files[index], rule, line: source.slice(0, match.index).split('\n').length });
    }
  }
}
assert.deepEqual(findings, [], `Potential credential found: ${JSON.stringify(findings)}`);

console.log(JSON.stringify({
  passed: true,
  version: manifest.version,
  files,
  applicationBytes: htmlBuffer.length,
  applicationSha256: sha256(htmlBuffer),
  inlineScripts: scripts.length,
  cspScriptHash: scriptHash,
  externalDependencies: externalReferences.length,
  potentialCredentials: findings.length,
  checks: ['file-allowlist', 'utf8-no-bom', 'application-sha256', 'version', 'script-syntax', 'csp', 'offline-dependencies', 'credential-patterns'],
  realVaultDataAccessed: false,
  realBusinessAcceptance: false,
}, null, 2));
