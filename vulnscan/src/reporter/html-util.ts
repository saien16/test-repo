/**
 * 複数のHTMLフォーマッタが共有する組み立て部品。
 *
 * html.ts と architecture-map.ts は同一のドキュメントへ出力するため、
 * 表のDOM構造を共有する必要がある。ただし html.ts が architecture-map.ts を
 * import している（セクションの埋め込み）ので、逆向きに import すると
 * 循環参照になる。共有部品はこちらに置いて双方から参照する。
 */

/**
 * テーブルは必ず横スクロールコンテナで包む。
 *
 * このレポートの表はすべて同じ CSS クラス（.table-scroll / table）に載る。
 * 別実装を増やすと DOM 構造を変えたときに片方だけ壊れるため、
 * 同一ドキュメントへ出力する側は必ずこれを使うこと。
 *
 * 引数はエスケープ済みのHTML断片であることを前提とする。
 * 呼び出し側で escapeHtml を通してから渡すこと。
 */
export function scrollTable(head: string[], rows: string[][], className = ''): string {
  const thead = head.map((h) => `<th scope="col">${h}</th>`).join('');
  const tbody = rows
    .map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`)
    .join('\n');
  return [
    '<div class="table-scroll" tabindex="0">',
    `<table class="${className}">`,
    `<thead><tr>${thead}</tr></thead>`,
    `<tbody>\n${tbody}\n</tbody>`,
    '</table>',
    '</div>',
  ].join('\n');
}
