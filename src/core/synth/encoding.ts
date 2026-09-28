// Real encodings, so evidence can be decoded the way an analyst would:
// PowerShell -EncodedCommand is base64 of UTF-16LE text. Implemented without
// btoa/Buffer so it behaves identically in browser, worker and Node.

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: ArrayLike<number>): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? B64[n & 63] : '=';
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array | null {
  const clean = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length === 0) return null;
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  const out: number[] = [];
  for (let i = 0; i < padded.length; i += 4) {
    const chunk = padded.slice(i, i + 4);
    const n =
      (B64.indexOf(chunk[0]) << 18) |
      (B64.indexOf(chunk[1]) << 12) |
      ((chunk[2] === '=' ? 0 : B64.indexOf(chunk[2])) << 6) |
      (chunk[3] === '=' ? 0 : B64.indexOf(chunk[3]));
    out.push((n >> 16) & 255);
    if (chunk[2] !== '=') out.push((n >> 8) & 255);
    if (chunk[3] !== '=') out.push(n & 255);
  }
  return new Uint8Array(out);
}

export function utf16leBase64(text: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    bytes.push(code & 255, code >> 8);
  }
  return bytesToBase64(bytes);
}

export function decodeUtf16le(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
  return s;
}

export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

// Best-effort decode used by the analyst's decode tool: detects UTF-16LE
// (PowerShell) vs UTF-8 payloads.
export function smartBase64Decode(b64: string): { text: string; encoding: 'utf-16le' | 'utf-8' } | null {
  const bytes = base64ToBytes(b64);
  if (!bytes || bytes.length === 0) return null;
  let zeros = 0;
  for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
  if (bytes.length >= 4 && zeros >= (bytes.length / 2) * 0.6) return { text: decodeUtf16le(bytes), encoding: 'utf-16le' };
  return { text: decodeUtf8(bytes), encoding: 'utf-8' };
}

// Base32 (RFC 4648, lowercase, no padding) — what DNS tunnels put in labels.
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
export function base32(bytes: ArrayLike<number>): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32ToBytes(text: string): Uint8Array | null {
  const clean = text.toLowerCase().replace(/=+$/, '');
  if (!/^[a-z2-7]+$/.test(clean)) return null;
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = ((value << 5) | B32.indexOf(ch)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

// Shannon entropy in bits per character: ~2.5–3.5 for words, 4.5+ for
// random-looking labels and encoded data.
export function entropy(text: string): number {
  if (!text) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

export function refang(value: string): string {
  return value.replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':');
}
