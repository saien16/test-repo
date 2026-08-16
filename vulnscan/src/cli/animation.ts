/**
 * スキャン実行中の進捗表示（魔法陣／詠唱モチーフ）。
 *
 * ■ このモジュールの責務
 *   CLI から渡された各ステージ（{@link STAGE_SEQUENCE}）の開始・進捗・終了を受け取り、
 *   端末に「今どこを詠唱しているか」を見せる。表示にまつわる判断
 *   （TTY判定・色・カーソル制御・描画間隔）を全部ここへ閉じ込め、
 *   `src/cli/index.ts` 側は hooks を繋ぐだけで済むようにする。
 *
 * ■ 実用性のために絶対に守っている制約
 *   1. **stderr にしか書かない**。stdout はレポート本体の出力先であり、
 *      `grimoire -f json > out.json` を壊してはならない。
 *   2. **TTY でなければアニメーションを出さない**。CI のログが
 *      エスケープシーケンスまみれになるのは論外なので、
 *      非TTY では1行ずつのプレーンなログへ落とす（{@link PlainAnimation}）。
 *   3. `quiet` なら完全に沈黙する（{@link SilentAnimation}）。
 *   4. `color=false` なら SGR を一切出さない（アニメーション自体は出す）。
 *   5. 終了・エラー・シグナル（SIGINT/SIGTERM）のいずれでも
 *      **必ずカーソルを戻して行を消す**。カーソルを隠したまま死ぬと
 *      端末が壊れたままになる。`stop()` は冪等で、多重呼び出しに耐える。
 *   6. 描画は同じ行の上書き。確定したステージだけを改行して積む。
 *   7. 更新は 12fps（80ms）。端末とCPUを無駄に焼かない。
 *   8. 端末幅を超えない（`reporter/text.ts` の表示幅計算を使う）。
 */

import { STAGE_SEQUENCE, type StageName, type StageProgress } from '../core/orchestrator.js';
import { createStyler, type Styler } from '../reporter/ansi.js';
import { displayWidth, truncate } from '../reporter/text.js';

/* ------------------------------------------------------------------ *
 * 公開インターフェース
 * ------------------------------------------------------------------ */

export interface ScanAnimation {
  /** 表示を開始する（カーソルを隠し、描画ループを回す） */
  start(): void;
  /** ステージの詠唱開始。`label` は人間向けの平易な名前 */
  stageStart(stage: StageName, label: string): void;
  /** 実行中のステージの処理件数を更新する */
  stageProgress(stage: StageName, progress: StageProgress): void;
  /** ステージの完了。`detail` は「87 件の候補」のような結果の要約 */
  stageEnd(stage: StageName, detail?: string): void;
  /** 後始末。**冪等**。カーソル復帰と行消去を必ず行う */
  stop(): void;
}

/** 出力先。テストから差し替えられるよう最小限の口だけ要求する */
export interface AnimationStream {
  write(chunk: string): unknown;
  columns?: number | undefined;
}

export interface AnimationOptions {
  /** 端末に繋がっているか。false ならプレーンなログへフォールバックする */
  tty: boolean;
  /** 色を使ってよいか */
  color: boolean;
  /** 完全に沈黙するか */
  quiet: boolean;
  /** 出力先（既定は process.stderr）。stdout は絶対に渡さないこと */
  stream?: AnimationStream;
  /** 描画間隔[ms]（既定 80ms = 12.5fps）。テスト用 */
  intervalMs?: number;
  /** 現在時刻の取得（既定は Date.now）。テスト用 */
  now?: () => number;
  /** シグナルハンドラを登録するか（既定 true）。テスト用に切れる */
  handleSignals?: boolean;
}

/* ------------------------------------------------------------------ *
 * 表示の語彙
 * ------------------------------------------------------------------ */

/**
 * 表示順。orchestrator のパイプライン順そのものを使う。
 *
 * 以前はここに同じ並びを手書きしており、`readonly StageName[]` という型では
 * 要素の欠落を検出できなかった（テストも STAGE_ORDER を回す形なので
 * 原理的に漏れを検出できない）。順序配列を1つにすることで
 * 「順序配列に足す」＝「型に足す」になる。
 */
export const STAGE_ORDER = STAGE_SEQUENCE;

/**
 * ステージの「詠唱名」。
 * 雰囲気は付けるが、括弧内に平易な名前を必ず併記して意味を潰さない。
 */
export const STAGE_SPELL: Readonly<Record<StageName, string>> = {
  context: '索敵',
  analyze: '解析詠唱',
  vuln: '照合',
  killchain: '連鎖演算',
  architecture: '構造把握',
  heatmap: '熱図描画',
  report: '編纂',
};

/*
 * 単位（「タスク」「候補」など）の対応表はここには置かない。
 * 進捗を報告するステージが {@link StageProgress} に載せて渡してくる。
 *
 * 以前はここに `STAGE_UNIT: Record<StageName, string>` があったが、
 * onProgress が配線されているのは②だけなので7件中6件は到達不能で、
 * 唯一使われる②の単位も「チャンク」と誤っていた
 * （実際に数えているのは レンズ×チャンク のタスク数）。
 * 表示側が推測で単位を決める構造そのものをやめてある。
 */

/**
 * 回転する魔法陣。
 * フォント依存が小さい U+25D0..U+25D3（塗り分けられた円）だけを使う。
 * 絵文字や罫線素片は端末によって幅が変わるので採らない。
 */
const RING_FRAMES = ['◐', '◓', '◑', '◒'] as const;

/** 進捗バーの文字。同じく BMP のブロック要素だけ */
const BAR_FILLED = '▓';
const BAR_EMPTY = '░';
const BAR_WIDTH = 12;

/** ANSI 制御列 */
const CSI = '\u001b[';
const HIDE_CURSOR = `${CSI}?25l`;
const SHOW_CURSOR = `${CSI}?25h`;
/** 行頭へ戻して行末まで消す（行の上書き用） */
const CLEAR_LINE = `\r${CSI}2K`;

const DEFAULT_INTERVAL_MS = 80; // 12.5fps
const DEFAULT_COLUMNS = 80;

/* ------------------------------------------------------------------ *
 * ファクトリ
 * ------------------------------------------------------------------ */

/**
 * 実行環境に合った実装を選ぶ。
 *
 *   quiet          → 何も出さない
 *   tty=false      → プレーンな1行ログ（エスケープを一切含まない）
 *   tty=true       → 魔法陣アニメーション
 */
export function createAnimation(opts: AnimationOptions): ScanAnimation {
  if (opts.quiet) return new SilentAnimation();
  const stream = opts.stream ?? process.stderr;
  if (!opts.tty) return new PlainAnimation(stream);
  return new LiveAnimation(stream, opts);
}

/* ------------------------------------------------------------------ *
 * ① 沈黙（--quiet）
 * ------------------------------------------------------------------ */

/** `--quiet` 用。一切書き込まない。 */
class SilentAnimation implements ScanAnimation {
  start(): void {}
  stageStart(): void {}
  stageProgress(): void {}
  stageEnd(): void {}
  stop(): void {}
}

/* ------------------------------------------------------------------ *
 * ② 非TTY（CIログ）向けのプレーン出力
 * ------------------------------------------------------------------ */

/**
 * 非TTY向けフォールバック。
 *
 * ANSI エスケープもカーソル制御も一切出さず、1イベント1行で追記する。
 * 進捗は毎回書くとログが膨れるので、25% 刻みの節目だけに間引く。
 */
class PlainAnimation implements ScanAnimation {
  /** 節目の割合（この値を跨いだときだけ1行出す） */
  private static readonly MILESTONES = [0.25, 0.5, 0.75] as const;

  /** 節目の報告済み割合。キーは局面がある場合 `stage:phase` */
  private readonly reported = new Map<string, number>();

  constructor(private readonly stream: AnimationStream) {}

  start(): void {
    this.line('GRIMOIRE — 禁書「九五九」を開きます');
  }

  stageStart(stage: StageName, label: string): void {
    this.reported.set(stage, 0);
    this.line(`▶ ${label} ...`);
  }

  stageProgress(stage: StageName, progress: StageProgress): void {
    const { completed, total, unit, phase } = progress;
    if (total <= 0) return;
    const ratio = completed / total;
    // 局面ごとに節目を数え直す。同じステージでも母数が変わるため、
    // 通しで見ると「50%まで戻った」ように見えてしまう。
    const key = phase ? `${stage}:${phase}` : stage;
    const done = this.reported.get(key) ?? 0;
    let next = done;
    for (const m of PlainAnimation.MILESTONES) {
      if (ratio >= m && m > done) next = m;
    }
    if (next === done) return;
    this.reported.set(key, next);
    const where = phase ? `${phase} ` : '';
    this.line(`  ${where}${completed}/${total} ${unit} (${Math.round(ratio * 100)}%)`);
  }

  stageEnd(stage: StageName, detail?: string): void {
    this.line(`✔ ${STAGE_SPELL[stage]}${detail ? ` — ${detail}` : ''}`);
  }

  stop(): void {
    // 何も隠していないので戻すものは無い
  }

  private line(text: string): void {
    this.stream.write(`${text}\n`);
  }
}

/* ------------------------------------------------------------------ *
 * ③ TTY 向けの魔法陣アニメーション
 * ------------------------------------------------------------------ */

interface StageState {
  label: string;
  completed: number;
  total: number;
  /** 進捗が来るまでは単位が判らないので空。バーもその間は出さない */
  unit: string;
  /** 局面名（②の 走査 / 自己検証）。無い場合もある */
  phase: string | null;
  startedAt: number;
}

/**
 * 行を上書きしながら魔法陣を回す実装。
 *
 * 画面に残すのは「確定したステージ」の行だけで、実行中の行は常に
 * 同じ1行を書き換える。カーソル移動（上方向）を使わないので、
 * 端末のリサイズや途中の別出力が混ざっても表示が破綻しない。
 */
class LiveAnimation implements ScanAnimation {
  private readonly stream: AnimationStream;
  private readonly styler: Styler;
  private readonly intervalMs: number;
  private readonly now: () => number;
  private readonly handleSignals: boolean;

  private timer: NodeJS.Timeout | null = null;
  private frame = 0;
  private startedAt = 0;
  private current: StageName | null = null;
  private state: StageState | null = null;
  /** 実行中の行が端末に出ているか（消すべきかの判断に使う） */
  private dirty = false;
  private started = false;
  private stopped = false;

  private readonly onSignal: (signal: NodeJS.Signals) => void;
  private readonly onExit: () => void;

  constructor(stream: AnimationStream, opts: AnimationOptions) {
    this.stream = stream;
    this.styler = createStyler(opts.color);
    this.intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.now = opts.now ?? Date.now;
    this.handleSignals = opts.handleSignals !== false;

    // シグナルで死ぬときもカーソルを戻す。
    // 自前のハンドラを外してから同じシグナルを再送し、
    // Node 既定の終了処理（および他のリスナ）へそのまま委ねる。
    this.onSignal = (signal: NodeJS.Signals): void => {
      this.stop();
      process.off('SIGINT', this.onSignal);
      process.off('SIGTERM', this.onSignal);
      process.kill(process.pid, signal);
    };
    // 最後の砦。何が起きても隠したカーソルは戻す（同期処理のみ）。
    this.onExit = (): void => {
      this.stop();
    };
  }

  start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.startedAt = this.now();

    if (this.handleSignals) {
      process.on('SIGINT', this.onSignal);
      process.on('SIGTERM', this.onSignal);
      process.on('exit', this.onExit);
    }

    this.stream.write(HIDE_CURSOR);
    // 見出しも必ず幅に収める（狭い端末で折り返すと以降の上書きが崩れる）
    this.writeFixed(
      this.fit(
        `${this.styler.magenta('✦')} ${this.styler.bold('GRIMOIRE')} ` +
          this.styler.gray('— 禁書「九五九」を開きます'),
      ),
    );

    this.timer = setInterval(() => this.render(), this.intervalMs);
    // 描画タイマーがプロセスの終了を引き延ばさないようにする
    this.timer.unref?.();
  }

  stageStart(stage: StageName, label: string): void {
    if (this.stopped) return;
    this.current = stage;
    this.state = { label, completed: 0, total: 0, unit: '', phase: null, startedAt: this.now() };
    this.render();
  }

  stageProgress(stage: StageName, progress: StageProgress): void {
    if (this.stopped || this.current !== stage || !this.state) return;
    this.state.completed = progress.completed;
    this.state.total = progress.total;
    this.state.unit = progress.unit;
    this.state.phase = progress.phase ?? null;
    // 描画自体はタイマーに任せる（呼び出し頻度に引きずられないため）
  }

  stageEnd(stage: StageName, detail?: string): void {
    if (this.stopped) return;
    const state = this.current === stage ? this.state : null;
    const elapsed = state ? this.now() - state.startedAt : 0;
    this.writeFixed(this.finishedLine(stage, state?.label ?? '', detail, elapsed));
    this.current = null;
    this.state = null;
  }

  stop(): void {
    if (this.stopped) return;
    this.stopped = true;

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.handleSignals) {
      process.off('SIGINT', this.onSignal);
      process.off('SIGTERM', this.onSignal);
      process.off('exit', this.onExit);
    }

    // 実行中の行を消してからカーソルを戻す。
    // start() を呼んでいなくても復帰列は出す（隠したままにする事故を避ける）。
    this.stream.write(`${CLEAR_LINE}${SHOW_CURSOR}`);
    this.dirty = false;
  }

  /* --- 描画 --- */

  /** 実行中の行を書き換える */
  private render(): void {
    if (this.stopped) return;
    this.frame = (this.frame + 1) % RING_FRAMES.length;
    const line = this.runningLine();
    if (line === null) {
      // 実行中のステージが無い間は行を空けておく
      if (this.dirty) {
        this.stream.write(CLEAR_LINE);
        this.dirty = false;
      }
      return;
    }
    this.stream.write(`${CLEAR_LINE}${line}`);
    this.dirty = true;
  }

  /** 確定行を1行積む（実行中の行は消してから書く） */
  private writeFixed(line: string): void {
    this.stream.write(`${CLEAR_LINE}${line}\n`);
    this.dirty = false;
  }

  private runningLine(): string | null {
    const stage = this.current;
    const state = this.state;
    if (stage === null || state === null) return null;

    const s = this.styler;
    const ring = s.magenta(RING_FRAMES[this.frame % RING_FRAMES.length] as string);
    const index = s.gray(`[${stageIndex(stage)}/${STAGE_ORDER.length}]`);
    const spell = s.cyan(STAGE_SPELL[stage]);
    const clock = s.gray(formatClock(this.now() - this.startedAt));

    const parts = [ring, index, spell];
    if (state.total > 0) {
      // 局面名を添える。②はここが「走査」→「自己検証」と変わり、
      // 同時に母数も変わる。名前が無いとバーが巻き戻ったようにしか見えない。
      if (state.phase) parts.push(s.dim(state.phase));
      parts.push(s.dim(renderBar(state.completed, state.total)));
      parts.push(`${state.completed}/${state.total} ${state.unit}`);
    } else {
      parts.push(s.dim(state.label));
    }
    parts.push(clock);

    return this.fit(parts.join(' '));
  }

  private finishedLine(
    stage: StageName,
    label: string,
    detail: string | undefined,
    elapsedMs: number,
  ): string {
    const s = this.styler;
    const head =
      `${s.green('✔')} ${s.gray(`[${stageIndex(stage)}/${STAGE_ORDER.length}]`)} ` +
      `${s.cyan(STAGE_SPELL[stage])}`;
    const body = label ? s.dim(`（${label}）`) : '';
    const tail = detail ? ` — ${detail}` : '';
    // 確定行の時計は「そのステージに掛かった時間」。
    // 実行中の行に出す総経過時間と取り違えないよう `+` を付けて区別する。
    return this.fit(`${head}${body}${tail} ${s.gray(`+${formatClock(elapsedMs)}`)}`);
  }

  /** 端末幅に収める。折り返しが起きると上書きが崩れるので必ず通す。 */
  private fit(line: string): string {
    const columns = this.stream.columns ?? DEFAULT_COLUMNS;
    // 右端ぴったりに書くと端末によっては自動改行が入るので1桁余らせる
    const limit = Math.max(8, columns - 1);
    return displayWidth(line) <= limit ? line : truncate(line, limit);
  }
}

/* ------------------------------------------------------------------ *
 * 小道具
 * ------------------------------------------------------------------ */

/** ステージの通し番号（1始まり）。未知のステージは 0 を返さず末尾扱いにする */
function stageIndex(stage: StageName): number {
  const i = STAGE_ORDER.indexOf(stage);
  return i >= 0 ? i + 1 : STAGE_ORDER.length;
}

/** `▓▓▓▓░░░░░░░░` 形式の進捗バー */
export function renderBar(completed: number, total: number, width = BAR_WIDTH): string {
  if (total <= 0) return BAR_EMPTY.repeat(width);
  const ratio = Math.max(0, Math.min(1, completed / total));
  const filled = Math.round(ratio * width);
  return BAR_FILLED.repeat(filled) + BAR_EMPTY.repeat(Math.max(0, width - filled));
}

/** 経過時間を `0:07` / `12:34` / `1:02:03` 形式に */
export function formatClock(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const sec = total % 60;
  const min = Math.floor(total / 60) % 60;
  const hour = Math.floor(total / 3600);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return hour > 0 ? `${hour}:${pad(min)}:${pad(sec)}` : `${min}:${pad(sec)}`;
}

/** テスト・診断用に制御列を公開する */
export const ANSI = {
  HIDE_CURSOR,
  SHOW_CURSOR,
  CLEAR_LINE,
} as const;
