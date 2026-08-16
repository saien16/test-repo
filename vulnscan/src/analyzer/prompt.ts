/**
 * user プロンプト（可変部分）の組み立て。
 * system 側はレンズ定義・検証プロンプトで固定されており、
 * ここには毎回変わる内容だけを置く（プロンプトキャッシュを効かせるため）。
 */

import type { ChunkContext } from './context.js';
import type { Chunk } from './types.js';

/** 行番号付きコードブロック */
export function buildCodeBlock(chunk: Chunk): string {
  return ['# コード（行頭の数字は実ファイルの行番号）', '```', chunk.code, '```'].join('\n');
}

/** 分析パス（1st pass）の user プロンプト */
export function buildAnalysisPrompt(chunkContext: ChunkContext): string {
  return [
    chunkContext.text,
    '',
    buildCodeBlock(chunkContext.chunk),
    '',
    '# 依頼',
    'このレンズの観点から、上のコードに実在する脆弱性を洗い出してください。',
    'location と dataFlow の行番号には、コードに付いている実ファイルの行番号を使ってください。',
    '該当が無ければ findings は空配列で構いません。',
  ].join('\n');
}
