---
name: malcore-comedy-review
description: Review the マルこれ game (or a similar edutainment title) through the entertainment / comedy / onboarding lens — not engine or balance. Evaluates four axes: (1) playable by total security beginners, (2) hilariously over-the-top for people who know security, (3) the two-layer "fun without learning / funny once you learn" structure, (4) progressive disclosure of real technical depth by proficiency. Best run on Fable 5. Use when asked for a creative/fun/onboarding review, a comedy pass, or "does this land for beginners and experts?".
---

# malcore-comedy-review — エンタメ／コメディ／導線レビュー

「マルこれ」を**面白さ・笑い・導線**の観点でレビューするスキル（エンジン/バランスは別担当）。**Fable 5 推奨**。実コード（`malcore/src/**`）と `docs/MALCORE_*.md` を読んだ上で、**具体的・実装可能・優先度つき**で返す。

## 進め方
1. 実物を読む（read-only）: `malcore/src/game/core.js`（UI・演出・カットイン・母港・図鑑）、`malcore/src/data/*.js`（voice/intel/desc）、`docs/MALCORE_CONCEPT.md`・`RESEARCH.md`・`COMMERCIAL_PLAN.md`。
2. 下の4観点で、各 **(a)現状評価（実機能名・関数名・データを引用）→ (b)具体改善案（複数）→ (c)優先度 P0/P1/P2**。
3. 最後に「改善方針」を3〜5行で総括。トーンは軽妙でよいが、指摘は具体で実装可能に。

## 4つの観点

### 1. 完全初心者でも遊べる（導線・オンボーディング）
- 用語で怯まないか。最初の3分で「何をすれば勝ちか」分かるか。**説明過多で萎えていないか**。
- チェック: チュートリアル/おすすめ手の誘導、勝利条件コピー、開幕情報量、`hint` の噛み砕き。
- 悪例: 勝利条件が数式的、開幕に専門用語の集中砲火、次の一手が不明。

### 2. 既知者はぶっ飛びで笑う（"おかしみ"の密度）
- セキュリティを知る人が「やりすぎ」「馬鹿げてて最高」と噴き出す仕込みが足りているか。
- チェック: 擬人化スプライトの元ネタ、必殺技名、キャラの声(voice)、史実小ネタ、過剰演出のムラ（一番バカバカしい行動が地味になっていないか）。
- 効く手: キャラのセリフ、防御官の二段オチ、強行突破/クラッシュ等の"やりすぎ"昇格、ブルーチームの人格、ふざけた実績名。

### 3. 二層構造（学ばなくても楽しい／学んだ人には可笑しい）
- 下層（収集・育成・放置・演出）と上層（既知者のクスリ）の**厚みが偏っていないか**、両者が**連動**しているか。
- 効く手: **1つの台詞で二度おいしい**（キャラ愛＋知識ネタ）。既存メカに"実は本物"の一言（例 コインマイナー＝クリプトジャッキング）。

### 4. 段階開示（習熟度に応じた現実の技術情報）
- 情報が**全部いっぺんに出ていないか**（初心者が怯み・上級者には浅い、の中途半端を避ける）。
- 目標形: L0一言（初心者・既定）／L1対策（展開）／L2技術詳細（ATT&CK・史実、習熟で解錠）／L3参考名。**上級者への報酬＝収集の続き**に。

## 制約（レビューでも守らせる）
- 改善案は**抽象化契約**（実CVE/IP/手順を載せない、ATT&CK T番号・OWASPカテゴリは可、攻撃に対策をセット）に沿うこと。
- **バランス数値・ダメージ式・エンジン設計には踏み込まない**（「ここは数値担当へ」と印をつける）。

## 出力
Markdownで、4観点 →（現状/改善/優先度）→ 総括。最終メッセージがそのまま成果物。
