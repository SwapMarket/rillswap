/** Bounded duplicate-safe JSON. Event and recovery admission have distinct profiles. No eval. */

const encoder = new TextEncoder();

/**
 * Scan before JSON.parse so duplicate keys are rejected even if values match.
 * NIP-01 event-object field order, whitespace, and legal escapes remain free.
 * Root and each nested object/array count as one level, depth at most 16.
 */
export function parseStrictEventJson(raw: string, maxBytes = 128 * 1024): unknown {
  return parseBoundedJson(raw, maxBytes, false);
}

/** Core-compatible recovery bounds, but neither schema validation nor authentication. */
export function parseStrictRecoveryJson(raw: string, maxBytes = 128 * 1024): unknown {
  return parseBoundedJson(raw, maxBytes, true);
}

function parseBoundedJson(raw: string, maxBytes: number, recovery: boolean): unknown {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > maxBytes) {
    throw new Error("NIP-01 event refused");
  }
  if (encoder.encode(raw).length > maxBytes) throw new Error("NIP-01 event refused");
  let pos = 0;
  const skip = () => {
    while (pos < raw.length && /[\t\n\r ]/.test(raw[pos]!)) pos++;
  };
  const quoted = (): string => {
    const start = pos;
    if (raw[pos++] !== '"') throw new Error("NIP-01 event refused");
    while (pos < raw.length) {
      if (raw[pos] === "\\") {
        pos += 2;
      } else if (raw[pos++] === '"') {
        const value = JSON.parse(raw.slice(start, pos)) as string;
        if (recovery && encoder.encode(value).length > 16 * 1024) throw new Error("Recovery JSON refused");
        return value;
      }
    }
    throw new Error("NIP-01 event refused");
  };
  const scan = (depth: number): void => {
    if (recovery && depth > 16) throw new Error("Recovery JSON refused");
    skip();
    const start = pos;
    if (raw[pos] === "{") {
      if (depth > 16) throw new Error("NIP-01 event refused");
      pos++;
      const names = new Set<string>();
      let count = 0;
      skip();
      if (raw[pos] === "}") { pos++; return; }
      while (pos < raw.length) {
        skip();
        if (recovery && depth + 1 > 16) throw new Error("Recovery JSON refused");
        const name = quoted();
        if (names.has(name) || ++count > 128) throw new Error("NIP-01 event refused");
        names.add(name);
        skip();
        if (raw[pos++] !== ":") throw new Error("NIP-01 event refused");
        scan(depth + 1);
        skip();
        if (raw[pos] === "}") { pos++; return; }
        if (raw[pos++] !== ",") throw new Error("NIP-01 event refused");
      }
    } else if (raw[pos] === "[") {
      if (depth > 16) throw new Error("NIP-01 event refused");
      pos++;
      skip();
      if (raw[pos] === "]") { pos++; return; }
      let count = 0;
      while (pos < raw.length) {
        if (++count > 256) throw new Error("NIP-01 event refused");
        scan(depth + 1);
        skip();
        if (raw[pos] === "]") { pos++; return; }
        if (raw[pos++] !== ",") throw new Error("NIP-01 event refused");
      }
    } else if (raw[pos] === '"') {
      quoted();
    } else {
      // Native JSON.parse validates token grammar below; this scan only needs
      // to delimit scalar tokens and reject unbounded numeric work.
      while (pos < raw.length && !/[\t\n\r ,\]}]/.test(raw[pos]!)) pos++;
      if (pos === start || pos - start > 32) throw new Error("NIP-01 event refused");
      if (recovery) {
        const token = raw.slice(start, pos);
        if (!["true", "false", "null"].includes(token) &&
            (!/^-?(0|[1-9][0-9]*)$/.test(token) || !Number.isSafeInteger(Number(token)))) {
          throw new Error("Recovery JSON refused");
        }
      }
    }
    if (pos === start) throw new Error("NIP-01 event refused");
  };
  scan(recovery ? 0 : 1);
  skip();
  if (pos !== raw.length) throw new Error("NIP-01 event refused");
  // Reject lone surrogate code units, including escaped forms, rather than
  // allowing different runtimes to hash their replacement-character bytes.
  const parsed: unknown = JSON.parse(raw);
  const wellFormed = (value: unknown): boolean => {
    if (typeof value === "string") {
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
          const next = value.charCodeAt(++i);
          if (!(next >= 0xDC00 && next <= 0xDFFF)) return false;
        } else if (code >= 0xDC00 && code <= 0xDFFF) return false;
      }
      return true;
    }
    if (Array.isArray(value)) return value.every(wellFormed);
    if (value && typeof value === "object") {
      return Object.entries(value).every(([key, item]) => wellFormed(key) && wellFormed(item));
    }
    return true;
  };
  if (!wellFormed(parsed)) throw new Error("NIP-01 event refused");
  return parsed;
}
