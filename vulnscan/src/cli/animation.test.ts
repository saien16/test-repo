/**
 * 進捗アニメーションのテスト。
 *
 * ここで固定したいのは見た目ではなく「壊れない条件」:
 *   - 非TTYではエスケープシーケンスを一切出さない（CIログを汚さない）
 *   - --quiet では1バイトも書かない
 *   - stop() は冪等で、必ずカーソル復帰列を出す
 *   - 端末幅を超えない
 *   - stdout を触らない
 */

import { describe, expect, it, vi } from 'vitest';
import {
  ANSI,
  createAnimation,
  formatClock,
  renderBar,
  STAGE_ORDER,
  STAGE_SPELL,
  type AnimationStream,
} from './animation.js';
import { displayWidth, stripAnsi } from '../reporter/text.js';

/** 書き込み内容を溜めるだけの偽ストリーム */
function fakeStream(columns = 80): AnimationStream & { text: () => string; chunks: string[] } {
  const chunks: string[] = [];
  return {
    columns,
    chunks,
    write(chunk: string) {
      chunks.push(chunk);
      return true;
    },
    text: () => chunks.join(''),
  };
}

/** ANSI エスケープ（SGR・カーソル制御を含む）が1つでも含まれているか */
function hasEscape(text: string): boolean {
  return text.includes('\u001b');
}

/** SGR（色）が含まれているか */
function hasSgr(text: string): boolean {
  return /\u001b\[[0-9;]*m/.test(text);
}

/** SGR に限らず CSI 列を全部落とす（表示幅の検証用） */
function stripCsi(text: string): string {
  return text.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '');
}

/**
 * 端末に「1行として見える」単位へ分解する。
 * 実行中の行は `\r` で上書きされるので、改行だけで割ってはいけない。
 */
function visibleLines(text: string): string[] {
  return stripCsi(text)
    .split(/[\r\n]+/)
    .filter((l) => l !== '');
}

/** 一通りのライフサイクルを流す */
function drive(anim: ReturnType<typeof createAnimation>): void {
  anim.start();
  anim.stageStart('context', 'コンテキスト収集');
  anim.stageProgress('context', { completed: 5, total: 10, unit: 'ファイル' });
  anim.stageEnd('context', '128 ファイル');
  anim.stageStart('analyze', 'ソースコード分析');
  anim.stageProgress('analyze', { completed: 12, total: 87, unit: 'タスク', phase: '走査' });
  anim.stageProgress('analyze', { completed: 87, total: 87, unit: 'タスク', phase: '走査' });
  anim.stageEnd('analyze', '9 件の候補');
  anim.stop();
}

/* ------------------------------------------------------------------ *
 * 非TTY
 * ------------------------------------------------------------------ */

describe('非TTY環境', () => {
  it('エスケープシーケンスを一切出さない', () => {
    const stream = fakeStream();
    drive(createAnimation({ tty: false, color: true, quiet: false, stream }));
    const out = stream.text();
    expect(out.length).toBeGreaterThan(0);
    expect(hasEscape(out)).toBe(false);
    // カーソル制御も出さない
    expect(out).not.toContain(ANSI.HIDE_CURSOR);
    expect(out).not.toContain(ANSI.SHOW_CURSOR);
    expect(out).not.toContain('\r');
  });

  it('color=true を指定されても色を出さない（非TTYが優先）', () => {
    const stream = fakeStream();
    drive(createAnimation({ tty: false, color: true, quiet: false, stream }));
    expect(stripAnsi(stream.text())).toBe(stream.text());
  });

  it('ステージごとに独立した行として追記する', () => {
    const stream = fakeStream();
    drive(createAnimation({ tty: false, color: false, quiet: false, stream }));
    const lines = stream.text().split('\n').filter((l) => l !== '');
    expect(lines.length).toBeGreaterThanOrEqual(4);
    // 各書き込みが必ず改行で終わる＝行の上書きをしていない
    for (const chunk of stream.chunks) expect(chunk.endsWith('\n')).toBe(true);
    expect(stream.text()).toContain('▶ コンテキスト収集 ...');
    expect(stream.text()).toContain('128 ファイル');
  });

  it('進捗は節目だけに間引く（ログを溢れさせない）', () => {
    const stream = fakeStream();
    const anim = createAnimation({ tty: false, color: false, quiet: false, stream });
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    for (let i = 1; i <= 100; i++)
      anim.stageProgress('analyze', { completed: i, total: 100, unit: 'タスク' });
    anim.stageEnd('analyze');
    anim.stop();
    const progressLines = stream
      .text()
      .split('\n')
      .filter((l) => l.includes('タスク'));
    // 25% / 50% / 75% の3行だけ
    expect(progressLines.length).toBe(3);
    expect(progressLines[0]).toContain('25/100 タスク');
  });

  it('stop() を何度呼んでも追加の出力をしない', () => {
    const stream = fakeStream();
    const anim = createAnimation({ tty: false, color: false, quiet: false, stream });
    anim.start();
    anim.stop();
    const before = stream.text();
    anim.stop();
    anim.stop();
    expect(stream.text()).toBe(before);
  });
});

/* ------------------------------------------------------------------ *
 * --quiet
 * ------------------------------------------------------------------ */

describe('--quiet', () => {
  it('TTYでも非TTYでも完全に沈黙する', () => {
    for (const tty of [true, false]) {
      const stream = fakeStream();
      drive(createAnimation({ tty, color: true, quiet: true, stream }));
      expect(stream.text()).toBe('');
      expect(stream.chunks).toEqual([]);
    }
  });

  it('quiet はシグナルハンドラも登録しない', () => {
    const before = process.listenerCount('SIGINT');
    const anim = createAnimation({ tty: true, color: false, quiet: true, stream: fakeStream() });
    anim.start();
    expect(process.listenerCount('SIGINT')).toBe(before);
    anim.stop();
  });
});

/* ------------------------------------------------------------------ *
 * TTY アニメーション
 * ------------------------------------------------------------------ */

function ttyAnim(stream: AnimationStream, color = true, now?: () => number) {
  return createAnimation({
    tty: true,
    color,
    quiet: false,
    stream,
    handleSignals: false,
    ...(now ? { now } : {}),
  });
}

describe('TTY アニメーション', () => {
  it('start() でカーソルを隠し、stop() で必ず戻す', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream);
    anim.start();
    expect(stream.text()).toContain(ANSI.HIDE_CURSOR);
    expect(stream.text()).not.toContain(ANSI.SHOW_CURSOR);
    anim.stop();
    expect(stream.text()).toContain(ANSI.SHOW_CURSOR);
  });

  it('stop() は冪等で、2回目以降は何も足さない', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream);
    anim.start();
    anim.stop();
    const after = stream.text();
    anim.stop();
    anim.stop();
    expect(stream.text()).toBe(after);
    // 復帰列はちょうど1回
    expect(after.split(ANSI.SHOW_CURSOR).length - 1).toBe(1);
  });

  it('start() を呼んでいなくても stop() はカーソル復帰列を出す', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream);
    anim.stop();
    expect(stream.text()).toContain(ANSI.SHOW_CURSOR);
  });

  it('stop() 後はイベントを受けても何も書かない', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream);
    anim.start();
    anim.stop();
    const after = stream.text();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageProgress('analyze', { completed: 1, total: 2, unit: 'タスク' });
    anim.stageEnd('analyze', 'x');
    expect(stream.text()).toBe(after);
  });

  it('完了ステージは確定行として改行付きで積まれる', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream, false);
    anim.start();
    anim.stageStart('context', 'コンテキスト収集');
    anim.stageEnd('context', '128 ファイル');
    anim.stop();
    const out = stream.text();
    expect(out).toContain(STAGE_SPELL.context);
    expect(out).toContain('（コンテキスト収集）');
    expect(out).toContain('128 ファイル');
    expect(out).toContain(`[1/${STAGE_ORDER.length}]`);
  });

  it('実行中の行は上書き（\\r + 行消去）で書かれ、改行を積まない', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream, false);
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    const running = stream.chunks.filter((c) => c.includes(ANSI.CLEAR_LINE) && !c.endsWith('\n'));
    expect(running.length).toBeGreaterThan(0);
    for (const chunk of running) expect(chunk.startsWith(ANSI.CLEAR_LINE)).toBe(true);
    anim.stop();
  });

  it('LLM並列の処理件数を「12/87 タスク」形式で出す', () => {
    const stream = fakeStream();
    const anim = createAnimation({
      tty: true,
      color: false,
      quiet: false,
      stream,
      handleSignals: false,
      intervalMs: 1,
    });
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageProgress('analyze', { completed: 12, total: 87, unit: 'タスク' });
    // 進捗はタイマー描画に載るので、描画を1回強制する代わりに
    // 別ステージの確定表示を挟まずタイマーを待つ
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(stream.text()).toContain('12/87 タスク');
        anim.stop();
        resolve();
      }, 30);
    });
  });

  it('color=false なら SGR を出さない（カーソル制御は出してよい）', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream, false);
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageEnd('analyze', '9 件の候補');
    anim.stop();
    const out = stream.text();
    // SGR（\u001b[<n>m）が1つも無いこと
    expect(hasSgr(out)).toBe(false);
    // カーソル制御は使われている
    expect(out).toContain(ANSI.HIDE_CURSOR);
  });

  it('color=true なら SGR を出す', () => {
    const stream = fakeStream();
    const anim = ttyAnim(stream, true);
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageEnd('analyze', '9 件の候補');
    anim.stop();
    expect(hasSgr(stream.text())).toBe(true);
  });

  it('どの行も端末幅を超えない（全角混在・狭い端末でも）', () => {
    for (const columns of [20, 40, 80]) {
      const stream = fakeStream(columns);
      const anim = ttyAnim(stream, true);
      anim.start();
      for (const stage of STAGE_ORDER) {
        anim.stageStart(stage, 'とても長い日本語のステージ名'.repeat(4));
        anim.stageProgress(stage, { completed: 1234, total: 5678, unit: '件', phase: '走査' });
        anim.stageEnd(stage, '非常に長い詳細テキスト'.repeat(6));
      }
      anim.stop();
      for (const line of visibleLines(stream.text())) {
        expect(displayWidth(line), `columns=${columns}: ${line}`).toBeLessThanOrEqual(
          Math.max(8, columns - 1),
        );
      }
    }
  });

  it('columns 未設定の端末でも既定幅に収める', () => {
    const stream = fakeStream();
    delete (stream as { columns?: number }).columns;
    const anim = ttyAnim(stream, false);
    anim.start();
    anim.stageStart('analyze', 'あ'.repeat(200));
    anim.stageEnd('analyze', 'い'.repeat(200));
    anim.stop();
    for (const line of visibleLines(stream.text())) {
      expect(displayWidth(line)).toBeLessThanOrEqual(79);
    }
  });

  it('描画タイマーは 10〜15fps 相当に抑えられている', () => {
    vi.useFakeTimers();
    try {
      const stream = fakeStream();
      const anim = ttyAnim(stream, false);
      anim.start();
      anim.stageStart('analyze', 'ソースコード分析');
      const base = stream.chunks.length;
      vi.advanceTimersByTime(1000);
      const frames = stream.chunks.length - base;
      expect(frames).toBeGreaterThanOrEqual(10);
      expect(frames).toBeLessThanOrEqual(15);
      anim.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it('stop() で描画タイマーが止まる', () => {
    vi.useFakeTimers();
    try {
      const stream = fakeStream();
      const anim = ttyAnim(stream, false);
      anim.start();
      anim.stageStart('analyze', 'ソースコード分析');
      anim.stop();
      const after = stream.text();
      vi.advanceTimersByTime(5000);
      expect(stream.text()).toBe(after);
    } finally {
      vi.useRealTimers();
    }
  });

  it('SIGINT/SIGTERM のリスナは stop() で必ず外れる', () => {
    const beforeInt = process.listenerCount('SIGINT');
    const beforeTerm = process.listenerCount('SIGTERM');
    const beforeExit = process.listenerCount('exit');
    const anim = createAnimation({
      tty: true,
      color: false,
      quiet: false,
      stream: fakeStream(),
    });
    anim.start();
    expect(process.listenerCount('SIGINT')).toBe(beforeInt + 1);
    expect(process.listenerCount('SIGTERM')).toBe(beforeTerm + 1);
    expect(process.listenerCount('exit')).toBe(beforeExit + 1);
    anim.stop();
    expect(process.listenerCount('SIGINT')).toBe(beforeInt);
    expect(process.listenerCount('SIGTERM')).toBe(beforeTerm);
    expect(process.listenerCount('exit')).toBe(beforeExit);
  });

  it('既定の出力先は stderr（stdout を汚さない）', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      const anim = createAnimation({ tty: true, color: false, quiet: false });
      anim.start();
      anim.stageStart('analyze', 'ソースコード分析');
      anim.stageEnd('analyze', '9 件');
      anim.stop();
      expect(stderr).toHaveBeenCalled();
      expect(stdout).not.toHaveBeenCalled();
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
  });

  it('経過時間を表示する', () => {
    let t = 0;
    const stream = fakeStream();
    const anim = ttyAnim(stream, false, () => t);
    anim.start();
    anim.stageStart('context', 'コンテキスト収集');
    t = 7_400;
    anim.stageEnd('context', '128 ファイル');
    anim.stop();
    // 確定行はステージ所要時間なので `+` 付き
    expect(stream.text()).toContain('+0:07');
  });
});

/* ------------------------------------------------------------------ *
 * 小道具
 * ------------------------------------------------------------------ */

describe('renderBar', () => {
  it('割合に応じて塗り分ける', () => {
    expect(renderBar(0, 10, 10)).toBe('░'.repeat(10));
    expect(renderBar(10, 10, 10)).toBe('▓'.repeat(10));
    expect(renderBar(5, 10, 10)).toBe(`${'▓'.repeat(5)}${'░'.repeat(5)}`);
  });

  it('総数0・範囲外でも幅が一定に保たれる', () => {
    for (const [c, t] of [[0, 0], [5, 0], [-3, 10], [999, 10]] as const) {
      expect(renderBar(c, t, 12)).toHaveLength(12);
    }
  });
});

describe('formatClock', () => {
  it('分:秒 / 時:分:秒 に整形する', () => {
    expect(formatClock(0)).toBe('0:00');
    expect(formatClock(7_400)).toBe('0:07');
    expect(formatClock(65_000)).toBe('1:05');
    expect(formatClock(3_723_000)).toBe('1:02:03');
  });

  it('負値でも壊れない', () => {
    expect(formatClock(-100)).toBe('0:00');
  });
});

describe('ステージ語彙', () => {
  it('全ステージに詠唱名がある', () => {
    // 件数は直書きしない。ステージが増減してもこのテストは壊れず、
    // 「語彙の付け忘れ」だけを検出し続ける。
    expect(STAGE_ORDER.length).toBeGreaterThan(0);
    for (const stage of STAGE_ORDER) {
      expect(STAGE_SPELL[stage], stage).toBeTruthy();
    }
  });
});

/* ------------------------------------------------------------------ *
 * 単位と局面
 *
 * 以前は表示側がステージ名から単位を引いていた。進捗を出すステージは
 * ②だけなので表の6件は到達不能で、しかも②の単位「チャンク」は誤り
 * （実際に数えているのは レンズ×チャンク のタスク数）だった。
 * 単位は数える側が進捗と一緒に運ぶ、という前提をここで固定する。
 * ------------------------------------------------------------------ */

describe('進捗の単位と局面', () => {
  it('単位は渡されたものをそのまま出す（表示側は推測しない）', () => {
    const stream = fakeStream(200);
    // 実行中の行はタイマー描画に載るので、描画間隔を詰めて1回走らせる
    const anim = createAnimation({
      tty: true, color: false, quiet: false, stream, handleSignals: false, intervalMs: 1,
    });
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageProgress('analyze', { completed: 3, total: 9, unit: '候補' });
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(stream.text()).toContain('3/9 候補');
        expect(stream.text()).not.toContain('チャンク');
        anim.stop();
        resolve();
      }, 30);
    });
  });

  it('局面名が渡されれば実行中の行に添える', () => {
    const stream = fakeStream(200);
    const anim = createAnimation({
      tty: true, color: false, quiet: false, stream, handleSignals: false, intervalMs: 1,
    });
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    anim.stageProgress('analyze', { completed: 2, total: 14, unit: '候補', phase: '自己検証' });
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(stream.text()).toContain('自己検証');
        expect(stream.text()).toContain('2/14 候補');
        anim.stop();
        resolve();
      }, 30);
    });
  });

  it('非TTYでは局面ごとに節目を数え直す（バーの引き直しを取りこぼさない）', () => {
    // ②は 走査(85) を100%まで進めたあと 自己検証(14) を0から数え直す。
    // 節目をステージ単位で覚えていると、2つ目の局面は「もう75%報告済み」
    // と見なされて1行も出なくなる。
    const stream = fakeStream();
    const anim = createAnimation({ tty: false, color: false, quiet: false, stream });
    anim.start();
    anim.stageStart('analyze', 'ソースコード分析');
    for (let i = 1; i <= 85; i++) {
      anim.stageProgress('analyze', { completed: i, total: 85, unit: 'タスク', phase: '走査' });
    }
    for (let i = 1; i <= 14; i++) {
      anim.stageProgress('analyze', { completed: i, total: 14, unit: '候補', phase: '自己検証' });
    }
    anim.stageEnd('analyze', '11 件の候補');
    anim.stop();
    const lines = stream.text().split('\n');
    expect(lines.filter((l) => l.includes('走査') && l.includes('タスク')).length).toBe(3);
    expect(lines.filter((l) => l.includes('自己検証') && l.includes('候補')).length).toBe(3);
  });
});
