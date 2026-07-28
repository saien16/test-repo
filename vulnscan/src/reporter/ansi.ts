/**
 * ANSIエスケープによる色付け。ライブラリは使わず自前で持つ。
 * `options.color` が false のときは一切のエスケープを出さない。
 */

import type { Severity } from '../types/context.js';

const ESC = '\u001b[';

const SGR = {
  reset: `${ESC}0m`,
  bold: `${ESC}1m`,
  dim: `${ESC}2m`,
  italic: `${ESC}3m`,
  underline: `${ESC}4m`,
  inverse: `${ESC}7m`,
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  blue: `${ESC}34m`,
  magenta: `${ESC}35m`,
  cyan: `${ESC}36m`,
  white: `${ESC}37m`,
  gray: `${ESC}90m`,
  brightRed: `${ESC}91m`,
  brightGreen: `${ESC}92m`,
  brightYellow: `${ESC}93m`,
  brightBlue: `${ESC}94m`,
  brightMagenta: `${ESC}95m`,
  brightCyan: `${ESC}96m`,
  bgRed: `${ESC}41m`,
  bgYellow: `${ESC}43m`,
  black: `${ESC}30m`,
} as const;

export type SgrName = keyof typeof SGR;

/** 深刻度ごとの前景色 */
const SEVERITY_SGR: Record<Severity, SgrName[]> = {
  critical: ['brightRed', 'bold'],
  high: ['red'],
  medium: ['yellow'],
  low: ['cyan'],
  info: ['gray'],
};

export interface Styler {
  readonly enabled: boolean;
  /** 任意のSGRを適用 */
  apply(text: string, ...names: SgrName[]): string;
  bold(text: string): string;
  dim(text: string): string;
  underline(text: string): string;
  red(text: string): string;
  green(text: string): string;
  yellow(text: string): string;
  cyan(text: string): string;
  magenta(text: string): string;
  gray(text: string): string;
  /** 深刻度に応じた色 */
  severity(text: string, severity: Severity): string;
  /** 深刻度バッジ（反転表示） */
  badge(text: string, severity: Severity): string;
}

export function createStyler(enabled: boolean): Styler {
  const apply = (text: string, ...names: SgrName[]): string => {
    if (!enabled || names.length === 0 || text === '') return text;
    return names.map((n) => SGR[n]).join('') + text + SGR.reset;
  };
  return {
    enabled,
    apply,
    bold: (t) => apply(t, 'bold'),
    dim: (t) => apply(t, 'dim'),
    underline: (t) => apply(t, 'underline'),
    red: (t) => apply(t, 'red'),
    green: (t) => apply(t, 'green'),
    yellow: (t) => apply(t, 'yellow'),
    cyan: (t) => apply(t, 'cyan'),
    magenta: (t) => apply(t, 'magenta'),
    gray: (t) => apply(t, 'gray'),
    severity: (t, sev) => apply(t, ...(SEVERITY_SGR[sev] ?? [])),
    badge: (t, sev) => {
      if (!enabled) return t;
      const fg = sev === 'critical' || sev === 'high' ? SGR.white : SGR.black;
      const bg =
        sev === 'critical' || sev === 'high'
          ? `${ESC}41m`
          : sev === 'medium'
            ? `${ESC}43m`
            : sev === 'low'
              ? `${ESC}46m`
              : `${ESC}47m`;
      return `${bg}${fg}${SGR.bold}${t}${SGR.reset}`;
    },
  };
}
