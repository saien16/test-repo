/* build.mjs — src を連結して dist/index.html を生成する。
   ESモジュール化しない方針。ORDER順に <script> へ流し込む。
   使い方: node build.mjs  /  node build.mjs --watch */
import { readFileSync, writeFileSync, watch, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const R = (p) => resolve(__dir, p);

// 連結順（依存の都合）: データ → 音 → コア → 捕獲 → フィールド/CPU
const ORDER = [
  'src/data/bugs.js',
  'src/audio/sound.js',
  'src/game/core.js',
  'src/game/catch.js',
  'src/render/tiles.js',
  'src/field/field-cpu.js',
];

function build() {
  const css = readFileSync(R('src/styles.css'), 'utf8');
  const js = ORDER.map(f => {
    const code = readFileSync(R(f), 'utf8');
    return `\n/* ===== ${f} ===== */\n${code}`;
  }).join('\n');
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
