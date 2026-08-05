#!/usr/bin/env python3
"""Markdown（日本語）→ 印刷用HTML。Chromium の page.pdf に食わせる。

md2pdf.py の一般化版。表紙の文言を JSON で外から渡せるようにした
（資料が複数になったため、スクリプトを複製せずに済ませる）。

日本語の組版で気をつけている点:
  - 本文は IPAGothic（このホストに実在する唯一のまともな和文フォント）
  - IPAGothic は太字を持たない。合成太字は潰れるので強調は色でも示す
  - 表と引用はページ跨ぎで割らない。コードブロックは割る
    （長いYAMLに avoid を掛けると手前が半ページ空白になる）
"""
import html
import json
import re
import sys

import markdown

src, dst, meta_path = sys.argv[1], sys.argv[2], sys.argv[3]
meta = json.load(open(meta_path, encoding="utf-8"))
text = open(src, encoding="utf-8").read()

body = markdown.markdown(
    text,
    extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
)


def slug(s: str) -> str:
    """手書きの `#見出し` リンクと python-markdown の id を一致させる"""
    s = re.sub(r"<[^>]+>", "", s)
    s = s.lower().strip()
    s = re.sub(r"[^\w　-鿿゠-ヿ぀-ゟ\s-]", "", s)
    return re.sub(r"\s+", "-", s)


def stamp(m):
    lvl, attrs, inner = m.group(1), m.group(2), m.group(3)
    # toc 拡張が振った id は捨てる。残すと id が2つ並んだ不正なHTMLになる
    attrs = re.sub(r'\s*id="[^"]*"', "", attrs)
    return f'<h{lvl} id="{slug(inner)}"{attrs}>{inner}</h{lvl}>'


body = re.sub(r"<h([1-6])((?: [^>]*)?)>(.*?)</h\1>", stamp, body, flags=re.S)

# 先頭の <h1> は表紙と重複するので落とす
body = re.sub(r"^\s*<h1[^>]*>.*?</h1>", "", body, count=1, flags=re.S)

CSS = """
/* 余白とページ番号は Playwright 側（margin / footerTemplate）で指定する。
   ここで @bottom-center を使うと footerTemplate と二重に出る。 */
@page { size: A4; }

:root {
  --text: #1b1f24;
  --dim: #5a6470;
  --line: #d5dae0;
  --accent: #1d4ed8;
  --code-bg: #f5f6f8;
  --warn-bg: #fff8e6;
  --warn-line: #d99e00;
}

* { box-sizing: border-box; }

body {
  font-family: "IPAPGothic", "IPAGothic", sans-serif;
  color: var(--text);
  font-size: 10pt;
  line-height: 1.85;
  margin: 0;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

/* ---- 表紙 ---- */
.cover {
  height: 247mm;
  display: flex;
  flex-direction: column;
  justify-content: center;
  page-break-after: always;
  border-left: 3mm solid var(--accent);
  padding-left: 12mm;
}
.cover .kicker { font-size: 10pt; color: var(--dim); letter-spacing: .2em; margin-bottom: 6mm; }
.cover h1 { font-size: 28pt; margin: 0 0 4mm; border: 0; padding: 0; line-height: 1.35; }
.cover .sub { font-size: 12pt; color: var(--dim); line-height: 1.9; margin-bottom: 14mm; }
.cover .meta { font-size: 9pt; color: var(--dim); border-top: 1px solid var(--line); padding-top: 4mm; line-height: 1.8; }

/* ---- 見出し ---- */
h1, h2, h3, h4 { page-break-after: avoid; break-after: avoid; line-height: 1.5; }
h1 {
  font-size: 19pt; margin: 0 0 6mm;
  padding-bottom: 2.5mm; border-bottom: 2.5px solid var(--text);
}
h2 {
  font-size: 14.5pt; margin: 9mm 0 3.5mm;
  padding-bottom: 1.8mm; border-bottom: 1px solid var(--line);
  page-break-before: auto;
}
h3 { font-size: 11.5pt; margin: 6mm 0 2.5mm; color: #11305e; }
h4 { font-size: 10.5pt; margin: 5mm 0 2mm; color: var(--dim); }

p { margin: 0 0 3mm; }

ul, ol { margin: 0 0 3.5mm; padding-left: 6mm; }
li { margin-bottom: 1.2mm; }
li > ul, li > ol { margin-top: 1.2mm; margin-bottom: 0; }

strong { font-weight: bold; }
/* IPAGothic は太字を持たない。合成太字だけだと潰れるので色でも区別する */
p > strong, li > strong { color: #8a1b1b; }

a { color: var(--accent); text-decoration: none; }

code {
  font-family: "DejaVu Sans Mono", "IPAGothic", monospace;
  font-size: 8.6pt;
  background: var(--code-bg);
  padding: 0.4mm 1.2mm;
  border-radius: 1mm;
  border: 1px solid #e4e7ec;
}
pre {
  background: var(--code-bg);
  border: 1px solid #e0e4ea;
  border-left: 2.5mm solid #c3ccd8;
  border-radius: 1.2mm;
  padding: 3mm 4mm;
  margin: 0 0 4mm;
  overflow-x: hidden;
  /* あえて分割を許す。長いブロックに avoid を掛けると丸ごと次ページへ送られ、
     手前に半ページ以上の空白ができる。ページを跨いだコードの方が読みやすい。 */
  page-break-inside: auto;
  break-inside: auto;
}
pre code {
  background: none; border: 0; padding: 0;
  /* 端末出力や図は行間を詰める。1.6 だと枠線が間延びして図に見えなくなる */
  font-size: 8.2pt; line-height: 1.42;
  white-space: pre-wrap;
  word-break: break-all;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 0 0 4.5mm;
  font-size: 9pt;
  page-break-inside: avoid;
  break-inside: avoid;
}
th, td {
  border: 1px solid var(--line);
  padding: 1.8mm 2.5mm;
  text-align: left;
  vertical-align: top;
  line-height: 1.65;
}
th { background: #eef1f5; font-weight: bold; }
tr:nth-child(even) td { background: #fafbfc; }

blockquote {
  margin: 0 0 4mm;
  padding: 3mm 4mm;
  background: var(--warn-bg);
  border-left: 2.5mm solid var(--warn-line);
  border-radius: 0 1.2mm 1.2mm 0;
  page-break-inside: avoid;
}
blockquote p:last-child { margin-bottom: 0; }
blockquote pre { background: #fff; margin-top: 2.5mm; }

hr { border: 0; border-top: 1px solid var(--line); margin: 7mm 0; }

p, li { orphans: 2; widows: 2; }
"""

cover = f"""
<div class="cover">
  <div class="kicker">{html.escape(meta["kicker"])}</div>
  <h1>{meta["title"]}</h1>
  <div class="sub">{meta["sub"]}</div>
  <div class="meta">{meta["foot"]}</div>
</div>
"""

out = f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8">
<title>{html.escape(meta["doctitle"])}</title>
<style>{CSS}</style>
</head><body>
{cover}
{body}
</body></html>"""

open(dst, "w", encoding="utf-8").write(out)
print(f"wrote {dst} ({len(out)} bytes)")
