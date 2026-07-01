---
name: malcore-flavor
description: Write in-world flavor text for the マルこれ (Malware Collection) game — character voice lines, codex intel (L0–L3), the two-stage debrief, onboarding/hint copy, and "実は本物" one-liners — so output matches the game's data schemas and its abstraction (ethics) contract. Best run on Fable 5. Use when adding/editing malware or attack-card flavor, filling voice/intel fields, writing result-screen debriefs, or drafting Japanese UI copy for this game.
---

# malcore-flavor — マルこれ 世界観フレーバー執筆

「マルこれ」の**キャラの声・図鑑の読み物・二段オチ・オンボーディング文言**を、既存スキーマと抽象化契約を守って書くためのスキル。**Fable 5 推奨**（軽妙・キャラ立て・コメディが効く）。

## 0. まず読む
- `docs/MALCORE_FABLE5_SYSTEM_PROMPT.md`（役割・指針・契約の要約）
- `malcore/src/data/malware.js`, `cards.js`（既存の voice / intel の書きぶり）
- `malcore/src/game/core.js` の `popBanner` / `renderCodex`(intelBlock) / `renderResult`(二段オチ)（どこで表示されるか）

## 1. 最上位指針（外さない）
1. 初心者ファースト（用語で怯ませない・説明過多にしない）
2. 既知者は笑う（史実小ネタ・過剰演出・擬人化のノリ）
3. 一石二鳥（1つの台詞でキャラ愛＋知識ネタ）
4. 段階開示（初心者には隠し、上級者には報酬）

## 2. 抽象化契約（絶対厳守・CIが機械チェック＝ `malcore/test/sim.mjs` シナリオ23）
- **禁止**: 実CVE番号、実IP/ホスト/鍵、コピペで動くコマンド、外部URL、手順の具体。
- **OK**: ATT&CK の T番号 / OWASP カテゴリ（分類であって手順ではない）、実在マルウェア名（歴史的アーキタイプとして）。
- 攻撃には**必ず対策(defense)**をセットで。攻撃対象の組織は**架空**（例: X省）。
- 迷ったら抽象化し直す。lint に通す前提で書く（`node malcore/test/sim.mjs`）。

## 3. データスキーマ（ここに書き込む）
```js
// malware.js: MAL_VOICES[id]
voice: { idle: ['…','…'], attack: '…', crit: '…', hurt: '…（=対策の裏返し）' }
// malware.js: MAL_INTEL[id] / cards.js: CARD_INTEL[id]
intel: { L0: '一言(初心者向け)', notable: '史実の一言', real: '抽象的な技術解説(手順なし)',
         tag: 'ATT&CK T… / OWASP …',  // malwareのみ。cardは c.tactic を流用
         refs: ['MITRE ATT&CK T…','OWASP Cheat Sheet: …'] } // リンク不可・固有名のみ
```
- **L1(対策)** は既存 `defense` を再利用（新規に書かない）。
- **戦闘中カットイン**は L0＋声まで。ATT&CK等の深掘りは**図鑑に集約**（没入を切らない）。

## 4. 二段オチ（リザルト）
`renderResult` が `voice.crit`(勝) / `voice.hurt`(負) をボヤキに使う。**ボヤキ＝対策の裏返し**にすると、`debrief()` の防御官ツッコミと噛み合って笑い＋学びが同時に立つ。
例: Zeus hurt「MFAさえ無ければ…！」→ 防御官「その通り。だからMFAを入れよう」。

## 5. 文体・型（実例）
- 必殺技名: カタカナ＋「！！」（例「マン・イン・ザ・ブラウザ！！」）。
- voice例: Mirai idle「IoT機器、あと4億台」/ CryptoLocker attack「暗号化、開始します」crit「身代金、お待ちしてます」。
- L0例（一言）: sqli「入力欄からDBに命令を"注射"して中身を吸い出す」。
- notable例（史実）: mirai「2016年。史上最大級のDDoSでDynを落とした。ソース公開で亜種が氾濫」。
- "実は本物"一言: コインマイナー設置に「※これ実在の"クリプトジャッキング"。あなたのCPUで勝手に採掘されてたら…？」。

## 6. 仕上げチェックリスト
- [ ] 初心者が読んで怯まないか（L0/hint は用語を噛み砕いたか）
- [ ] 既知者がニヤリとする小ネタが1つ以上あるか
- [ ] hurt が対策の裏返しになっているか
- [ ] 攻撃に defense が対応しているか
- [ ] 実CVE/IP/コマンド/URLが無いか（`node malcore/test/sim.mjs` が緑か）
- [ ] スキーマの型・キー名に合っているか（merge map に追記 → `MAL/CARDS.forEach` で反映）
