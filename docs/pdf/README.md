# 配布用PDFの作り方

`docs/` の文書と `docs/web/` の紹介ページを、印刷向けに組み直して PDF にします。

| 出力 | 入力 | 経路 |
| --- | --- | --- |
| GRIMOIRE-はじめてのガイド.pdf | `docs/getting-started.md` | `mkpdf.py` → `topdf.mjs` |
| GRIMOIRE-設計書.pdf | `docs/vuln-scanner-design.md` | `mkpdf.py` → `topdf.mjs` |
| GRIMOIRE-サービス紹介.pdf | `docs/web/grimoire-service.html` | `htmlpdf.mjs` |
| GRIMOIRE-3分でわかる超入門.pdf | `docs/web/grimoire-beginner.html` | `htmlpdf.mjs` |

Web UI デモ（`docs/web/grimoire-webui.html`）は操作して意味が出る画面なので PDF にしていません。

## 実行

```bash
# Markdown → 印刷用HTML → PDF
python3 docs/pdf/mkpdf.py docs/getting-started.md /tmp/guide.html docs/pdf/cover-guide.json
node docs/pdf/topdf.mjs /tmp/guide.html "GRIMOIRE-はじめてのガイド.pdf"

# 画面用HTML → PDF（第4引数は縮小率）
node docs/pdf/htmlpdf.mjs \
  "$PWD/docs/web/grimoire-service.html" "GRIMOIRE-サービス紹介.pdf" \
  docs/pdf/print-service.css 0.7
```

`playwright` を解決できる場所（`vulnscan/`）から実行してください。ESM の解決は
スクリプトの位置を基準にするため、`node_modules` が見える場所に置くか
シンボリックリンクを張る必要があります。

## この環境でつまずいた点

**和文フォントは IPAGothic しか無い。** 明朝（Hiragino / Noto Serif JP）の指定は
そのままだと Unifont のビットマップ字形に落ちるため、印刷時にゴシックへ差し替えています。
IPAGothic は太字を持たないので、強調は合成太字ではなく色でも示します。

**コードブロックにページ跨ぎを禁止しない。** 長い YAML に `page-break-inside: avoid`
を掛けると、入りきらない塊が丸ごと次ページへ送られ、手前が半ページ以上の白紙になります。
跨いだコードの方が白紙よりはるかに読みやすい。

**紹介ページはスクロールで要素を出す（`.reveal`）。** そのまま印刷すると画面外の要素が
`opacity: 0` のまま刷られ、2ページ目以降がほぼ白紙になります。
`reducedMotion: 'reduce'` を渡してページ側のアクセシビリティ経路に乗せ、
最初から全て見えている状態にしています。

**外側の大きなカードには `break-inside: avoid` を掛けない。** 割れて困る最小単位
（1項目・1ステップ）にだけ掛けます。外側に掛けるとページ下半分が空きます。

**ページ番号は Playwright の `footerTemplate` だけで出す。** CSS の `@page` と併用すると
二重に出ます。Chromium 既定のヘッダ（日時＋タイトル）は空の `headerTemplate` で潰します。
