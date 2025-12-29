type DiffEdit =
  | { type: 'equal'; line: string }
  | { type: 'insert'; line: string }
  | { type: 'delete'; line: string };

function myersDiff(oldLines: string[], newLines: string[]): DiffEdit[] {
  const n = oldLines.length;
  const m = newLines.length;
  const max = n + m;
  const offset = max;
  let v = new Array<number>(2 * max + 1).fill(0);
  const trace: number[][] = [];

  for (let d = 0; d <= max; d += 1) {
    const vSnapshot = v.slice();
    for (let k = -d; k <= d; k += 2) {
      const kIndex = k + offset;
      const down = k === -d || (k !== d && v[kIndex - 1] < v[kIndex + 1]);
      let x = down ? v[kIndex + 1] : v[kIndex - 1] + 1;
      let y = x - k;
      while (x < n && y < m && oldLines[x] === newLines[y]) {
        x += 1;
        y += 1;
      }
      vSnapshot[kIndex] = x;
      if (x >= n && y >= m) {
        trace.push(vSnapshot);
        return backtrackEdits(oldLines, newLines, trace, offset);
      }
    }
    trace.push(vSnapshot);
    v = vSnapshot;
  }

  return [];
}

function backtrackEdits(
  oldLines: string[],
  newLines: string[],
  trace: number[][],
  offset: number,
): DiffEdit[] {
  const edits: DiffEdit[] = [];
  let x = oldLines.length;
  let y = newLines.length;

  for (let d = trace.length - 1; d >= 0; d -= 1) {
    const v = trace[d];
    const k = x - y;
    const kIndex = k + offset;
    const down = k === -d || (k !== d && v[kIndex - 1] < v[kIndex + 1]);
    const prevK = down ? k + 1 : k - 1;
    const prevX = v[prevK + offset];
    const prevY = prevX - prevK;

    while (x > prevX && y > prevY) {
      edits.push({ type: 'equal', line: oldLines[x - 1] });
      x -= 1;
      y -= 1;
    }

    if (d === 0) {
      break;
    }

    if (down) {
      edits.push({ type: 'insert', line: newLines[y - 1] });
      y -= 1;
    } else {
      edits.push({ type: 'delete', line: oldLines[x - 1] });
      x -= 1;
    }
  }

  return edits.reverse();
}

function buildUnifiedHunks(
  oldLines: string[],
  newLines: string[],
  edits: DiffEdit[],
  context: number,
): string[] {
  const hunks: string[] = [];
  let oldLine = 1;
  let newLine = 1;
  let hunkLines: string[] = [];
  let hunkOldStart = 0;
  let hunkNewStart = 0;
  let hunkOldCount = 0;
  let hunkNewCount = 0;
  let contextBuffer: DiffEdit[] = [];

  const flushHunk = (): void => {
    if (hunkLines.length === 0) {
      return;
    }
    hunks.push(
      `@@ -${hunkOldStart},${hunkOldCount} +${hunkNewStart},${hunkNewCount} @@`,
    );
    hunks.push(...hunkLines);
    hunkLines = [];
    hunkOldStart = 0;
    hunkNewStart = 0;
    hunkOldCount = 0;
    hunkNewCount = 0;
  };

  for (const edit of edits) {
    if (edit.type === 'equal') {
      if (hunkLines.length === 0) {
        contextBuffer.push(edit);
        if (contextBuffer.length > context) {
          contextBuffer.shift();
        }
      } else {
        hunkLines.push(` ${edit.line}`);
        hunkOldCount += 1;
        hunkNewCount += 1;
        if (hunkLines.slice(-context).every((line) => line.startsWith(' '))) {
          const tail = hunkLines.slice(-context);
          flushHunk();
          contextBuffer = tail.map((line) => ({
            type: 'equal',
            line: line.slice(1),
          }));
        }
      }
      oldLine += 1;
      newLine += 1;
      continue;
    }

    if (hunkLines.length === 0) {
      hunkOldStart = Math.max(1, oldLine - contextBuffer.length);
      hunkNewStart = Math.max(1, newLine - contextBuffer.length);
      for (const ctx of contextBuffer) {
        hunkLines.push(` ${ctx.line}`);
        hunkOldCount += 1;
        hunkNewCount += 1;
      }
      contextBuffer = [];
    }

    if (edit.type === 'delete') {
      hunkLines.push(`-${edit.line}`);
      hunkOldCount += 1;
      oldLine += 1;
    } else {
      hunkLines.push(`+${edit.line}`);
      hunkNewCount += 1;
      newLine += 1;
    }
  }

  flushHunk();
  return hunks;
}

export function diffUnified(
  beforeText: string,
  afterText: string,
  options?: { context?: number },
): string {
  const context = options?.context ?? 3;
  const oldLines = beforeText.split(/\r?\n/);
  const newLines = afterText.split(/\r?\n/);
  const edits = myersDiff(oldLines, newLines);
  const hunks = buildUnifiedHunks(oldLines, newLines, edits, context);
  return hunks.join('\n');
}
