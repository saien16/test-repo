/**
 * 同時実行数を制限しながらタスクを流すワーカープール。
 * チャンク分析はここを通して並列化する。
 */

export interface PoolProgress {
  completed: number;
  total: number;
}

/**
 * `items` を最大 `concurrency` 並列で `worker` に流す。
 * 個々の失敗は結果配列に null として現れ、全体を止めない。
 */
export async function mapPool<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
  onProgress?: (p: PoolProgress) => void,
): Promise<(R | null)[]> {
  const results: (R | null)[] = new Array(items.length).fill(null);
  const limit = Math.max(1, Math.min(concurrency, items.length));
  let next = 0;
  let completed = 0;

  async function run(): Promise<void> {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      const item = items[index];
      if (item === undefined) return;
      try {
        results[index] = await worker(item, index);
      } catch {
        results[index] = null;
      }
      completed++;
      onProgress?.({ completed, total: items.length });
    }
  }

  await Promise.all(Array.from({ length: limit }, run));
  return results;
}
