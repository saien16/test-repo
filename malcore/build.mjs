/* build.mjs — マルこれ: src を連結して dist/index.html を生成する。
   むしとりバトルと同じ流儀（ESモジュール化しない・ORDER順に <script> へ連結）。
   使い方: node build.mjs  /  node build.mjs --watch */
import { readFileSync, writeFileSync, watch, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const R = (p) => resolve(__dir, p);

// 連結順（依存の都合）: データ → コア
const ORDER = [
  'src/data/malware.js',
  'src/data/enemies.js',
  'src/game/core.js',
];
const CSS_ORDER = ['src/styles.css'];

function build() {
  const css = CSS_ORDER
    .filter(f => existsSync(R(f)))
    .map(f => `/* ===== ${f} ===== */\n${readFileSync(R(f), 'utf8')}`)
    .join('\n');
  const js = ORDER.map(f => `\n/* ===== ${f} ===== */\n${readFileSync(R(f), 'utf8')}`).join('\n');
  let html = readFileSync(R('src/index.template.html'), 'utf8');
  html = html.replace('/*__CSS__*/', () => css);
  html = html.replace('/*__JS__*/', () => js);
  mkdirSync(R('dist'), { recursive: true });
  writeFileSync(R('dist/index.html'), html);
  const kb = (Buffer.byteLength(html) / 1024).toFixed(1);
  console.log(`built dist/index.html (${kb} KB) @ ${new Date().toISOString()}`);
}

build();

if (process.argv.includes('--watch')) {
  console.log('watching src/ …');
  let t = null;
  watch(R('src'), { recursive: true }, () => {
    clearTimeout(t); t = setTimeout(() => { try { build(); } catch (e) { console.error(e.message); } }, 120);
  });
}
