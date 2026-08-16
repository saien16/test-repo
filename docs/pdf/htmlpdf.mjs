/**
 * 画面用HTML（アーティファクト）→ 配布用PDF。
 *
 * 画面向けに作ったページなので、そのまま印刷すると次の3点で破綻する:
 *   1. ダークテーマで刷られる（配色は環境依存。紙では常にライトに固定する）
 *   2. 明朝フォント（Hiragino/Noto Serif JP）がこのホストに無く、和文が化ける
 *   3. カード・図がページ境界で真っ二つに割れる
 * それぞれ data-theme の固定・フォント差し替え・break-inside で潰す。
 *
 * レイアウトは崩さずに縮小して A4 に収める（scale）。
 * デスクトップ幅のグリッド（940px 以上）を保ったまま刷るため。
 */
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const [src, out, cssPath, scaleArg] = process.argv.slice(2);
const scale = Number(scaleArg ?? 0.7);

const browser = await chromium.launch({
  executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
});
// scale をかけた後の CSS 幅にビューポートを合わせる。
// ここがずれると、画面では出ていた 3〜7 カラムのグリッドが崩れる。
const width = Math.round(794 / scale);
const page = await browser.newPage({ viewport: { width, height: 1200 } });
// reducedMotion=reduce が要る。このページはスクロールで要素を出す（.reveal）ので、
// そのままだと画面外＝opacity:0 のまま刷られ、2ページ目以降がほぼ白紙になる。
// ページ側が持っている「動きを減らす」経路に乗せて、最初から全部見えている状態にする。
await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
await page.goto(`file://${src}`, { waitUntil: 'load' });

// テーマ切替ボタンを持つページは data-theme を見る。明示的にライトへ固定する
await page.evaluate(() => {
  document.documentElement.setAttribute('data-theme', 'light');
});

// canvas の印章・マークは JS が load 後に描く。2フレーム待って確定させる
await page.evaluate(
  () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))),
);

const common = `
  :root {
    /* このホストに和文明朝が無い。明朝指定はすべてゴシックへ落とす
       （指定のまま刷ると Unifont のビットマップ字形になる） */
    --serif-jp: "IPAPGothic", "IPAGothic", sans-serif !important;
    --sans: "IPAPGothic", "IPAGothic", sans-serif !important;
    --serif-latin: "DejaVu Serif", Georgia, serif !important;
    --mono: "DejaVu Sans Mono", monospace !important;
  }
  html, body { background: #fff !important; }
  * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
  /* 紙の上では押せないもの */
  .theme-btn, .hero-cta, .btn, [role="button"] { display: none !important; }
  /* 動きを止める（印刷時に途中の状態で固まると意味不明な絵になる） */
  *, *::before, *::after { animation: none !important; transition: none !important; }
  /* スクロール連動の出現演出は紙では成立しない。常時表示にする */
  .reveal, .reveal.in { opacity: 1 !important; transform: none !important; }
`;

await page.addStyleTag({ content: common + (cssPath ? readFileSync(cssPath, 'utf8') : '') });
await page.evaluate(
  () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))),
);

await page.pdf({
  path: out,
  format: 'A4',
  scale,
  printBackground: true,
  displayHeaderFooter: true,
  headerTemplate: '<div></div>',
  footerTemplate:
    '<div style="width:100%;text-align:center;font-size:8pt;color:#8a929c;' +
    'font-family:sans-serif;">' +
    '<span class="pageNumber"></span> / <span class="totalPages"></span></div>',
  margin: { top: '10mm', bottom: '14mm', left: '8mm', right: '8mm' },
});
await browser.close();
console.log(`ok ${out} (scale=${scale}, viewport=${width}px)`);
