// Punycode decoding (RFC 3492). Browsers hand extensions hostnames in their
// ASCII form, so "pаypal.com" with a Cyrillic а arrives as "xn--pypal-4ve.com".
// We need the real characters back to see what the user is looking at.

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
    delta = Math.floor(delta / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

function digitValue(ch) {
  const c = ch.charCodeAt(0);
  if (c >= 48 && c <= 57) return c - 22; // 0-9 -> 26-35
  if (c >= 97 && c <= 122) return c - 97; // a-z -> 0-25
  if (c >= 65 && c <= 90) return c - 65;
  throw new Error(`bad punycode digit ${ch}`);
}

function decodePunycode(input) {
  const output = [];
  const lastDash = input.lastIndexOf("-");
  for (let i = 0; i < Math.max(lastDash, 0); i++) {
    output.push(input.charCodeAt(i));
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  let pos = lastDash > 0 ? lastDash + 1 : 0;

  while (pos < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) throw new Error("truncated punycode");
      const digit = digitValue(input[pos++]);
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

export function decodeLabel(label) {
  if (!label.toLowerCase().startsWith("xn--")) return label;
  return decodePunycode(label.slice(4));
}

export function toUnicode(hostname) {
  try {
    return hostname.split(".").map(decodeLabel).join(".");
  } catch {
    return hostname;
  }
}
