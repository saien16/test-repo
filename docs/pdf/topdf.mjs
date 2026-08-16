import { chromium } from 'playwright';

const [html, out] = process.argv.slice(2);
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
const page = await browser.newPage();
await page.goto(`file://${html}`, { waitUntil: 'load' });
await page.pdf({
  path: out,
  format: 'A4',
  printBackground: true,
  displayHeaderFooter: true,
  // 既定のヘッダ（日時＋タイトル）は配布物に不要。空要素で潰す。
  headerTemplate: '<div></div>',
  // フッタはページ番号だけ。中央・9pt・薄いグレー。
  footerTemplate:
    '<div style="width:100%;text-align:center;font-size:8pt;color:#8a929c;' +
    'font-family:sans-serif;">' +
    '<span class="pageNumber"></span> / <span class="totalPages"></span></div>',
  margin: { top: '16mm', bottom: '18mm', left: '16mm', right: '16mm' },
});
await browser.close();
console.log('ok');
