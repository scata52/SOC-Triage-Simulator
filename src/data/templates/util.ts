import type { ArtifactFormat, LogArtifact, RubricItem } from '../../types.ts';

export function artifact(
  source: string,
  format: ArtifactFormat,
  lines: string[],
  caption?: string,
): LogArtifact {
  return { source, format, lines, caption };
}

// Render aligned "Key: value" lines.
export function kvBlock(pairs: [string, string | number][]): string[] {
  const width = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `${(k + ':').padEnd(width + 2)}${String(v)}`);
}

// Render a JSON object as indented lines.
export function jsonLines(obj: unknown): string[] {
  return JSON.stringify(obj, null, 2).split('\n');
}

// Render a fixed-width table from a header + rows.
export function table(header: string[], rows: string[][]): string[] {
  const widths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)),
  );
  const fmt = (cells: string[]) =>
    cells.map((c, i) => (c ?? '').padEnd(widths[i])).join('  ');
  return [fmt(header), widths.map((w) => '-'.repeat(w)).join('  '), ...rows.map(fmt)];
}

export function rubric(items: [string, string, string[]][]): RubricItem[] {
  return items.map(([id, text, keywords]) => ({ id, text, keywords }));
}

// Small helper to seconds-since-anchor a sequence of events.
export function everySeconds(start: number, step: number, count: number): number[] {
  return Array.from({ length: count }, (_, i) => start + i * step);
}
