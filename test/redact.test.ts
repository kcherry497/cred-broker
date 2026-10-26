import { test, expect, describe } from "bun:test";
import type { StreamRedactor as Redactor } from "../src/cred.ts";

// Only the redaction exports are exercised; nothing here reads a manifest. (yaml is not mocked:
// bun applies module mocks to every file in the run, which would break the other suites.)
const { buildPatterns, StreamRedactor } = await import("../src/cred.ts");

const MARKER: string = "[cred:test]";
const SEED: number = 0xc0ffee;
type Reference = { out: string; count: number };
type Run = { out: Buffer; count: number };
type Failure = {
  value: string;
  input: Buffer;
  boundaries: number[];
  expected: string;
  actual: string;
  expectedCount?: number;
  actualCount?: number;
  seed?: number;
  note?: string;
};
type Variant = { name: string; text: string };

function latin1(s: string): string {
  return utf8Bytes(s).toString("latin1");
}

function utf8Bytes(s: string): Buffer {
  return Buffer.from(s, "utf8");
}

// Whole-input oracle: non-overlapping, leftmost-longest; no streaming state.
function referenceRedact(input: string, patterns: string[], marker: string): Reference {
  let out: string = "";
  let count: number = 0;
  for (let i: number = 0; i < input.length;) {
    let longest: string = "";
    for (const pattern of patterns) {
      if (pattern.length > longest.length && input.startsWith(pattern, i)) longest = pattern;
    }
    if (longest.length > 0) {
      out += marker;
      count++;
      i += longest.length;
    } else {
      out += input[i];
      i++;
    }
  }
  return { out, count };
}

// Boundaries are absolute byte offsets; 0 and input.length deliberately test empty pushes.
function runChunked(redactor: Redactor, buf: Buffer, boundaries: number[]): Run {
  const output: Buffer[] = [];
  let start: number = 0;
  for (const end of boundaries) {
    if (!Number.isInteger(end) || end < start || end > buf.length) throw new Error("Invalid chunk boundary");
    output.push(redactor.push(buf.subarray(start, end)));
    start = end;
  }
  output.push(redactor.push(buf.subarray(start)), redactor.end());
  return { out: Buffer.concat(output), count: redactor.count };
}

function chunkings(length: number): number[][] {
  const result: number[][] = [];
  for (let split: number = 0; split <= length; split++) result.push([split]);
  result.push(Array.from({ length: Math.max(0, length - 1) }, (_: unknown, i: number) => i + 1));
  return result;
}

function compareFailures(a: Failure, b: Failure): number {
  if (a.input.length !== b.input.length) return a.input.length - b.input.length;
  if (a.boundaries.length !== b.boundaries.length) return a.boundaries.length - b.boundaries.length;
  for (let i: number = 0; i < a.boundaries.length; i++) {
    if (a.boundaries[i] !== b.boundaries[i]) return a.boundaries[i] - b.boundaries[i];
  }
  return Buffer.compare(a.input, b.input);
}

function failureMessage(failures: Failure[]): string {
  if (failures.length === 0) return "No failures";
  // Collect every result; report only the shortest input, then fewest/earliest boundaries.
  const f: Failure = [...failures].sort(compareFailures)[0];
  return "FIRST minimal failing case (among enumerated cases): " + JSON.stringify({
    value: f.value,
    input: f.input.toString("latin1"),
    inputHex: f.input.toString("hex"),
    boundaries: f.boundaries,
    expected: f.expected,
    actual: f.actual,
    expectedCount: f.expectedCount,
    actualCount: f.actualCount,
    seed: f.seed === undefined ? undefined : `0x${f.seed.toString(16)}`,
    note: f.note,
    failingCases: failures.length,
  });
}

function assertFailures(failures: Failure[]): void {
  expect(failures.length, failureMessage(failures)).toBe(0);
}

function recordComparison(
  failures: Failure[], value: string, input: Buffer, boundaries: number[], patterns: string[],
  expected: Reference = referenceRedact(input.toString("latin1"), patterns, MARKER),
  seed?: number, note?: string,
): void {
  const actual: Run = runChunked(new StreamRedactor(patterns, MARKER), input, boundaries);
  if (!actual.out.equals(Buffer.from(expected.out, "latin1")) || actual.count !== expected.count) {
    failures.push({ value, input, boundaries, expected: expected.out, actual: actual.out.toString("latin1"),
      expectedCount: expected.count, actualCount: actual.count, seed, note });
  }
}

function allSplits(value: string, input: Buffer, patterns: string[], expected?: Reference, note?: string): void {
  const failures: Failure[] = [];
  for (const boundaries of chunkings(input.length)) {
    recordComparison(failures, value, input, boundaries, patterns, expected, undefined, note);
  }
  assertFailures(failures);
}

function mulberry32(seed: number): () => number {
  let state: number = seed >>> 0;
  return (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let bits: number = Math.imul(state ^ (state >>> 15), state | 1);
    bits ^= bits + Math.imul(bits ^ (bits >>> 7), bits | 61);
    return ((bits ^ (bits >>> 14)) >>> 0) / 4294967296;
  };
}

function randomBoundaries(length: number, random: () => number): number[] {
  const result: number[] = [];
  for (let offset: number = 1; offset < length; offset++) if (random() < 0.35) result.push(offset);
  return result;
}

// Python ensure_ascii=True works on UTF-16 units here, including both surrogate halves.
function asciiJson(s: string): string {
  let out: string = "";
  const controls: Record<number, string> = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r" };
  for (let i: number = 0; i < s.length; i++) {
    const code: number = s.charCodeAt(i);
    if (code === 34) out += '\\"';
    else if (code === 92) out += "\\\\";
    else if (controls[code] !== undefined) out += controls[code];
    else if (code < 32 || code >= 127) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += s[i];
  }
  return out;
}

function expectedVariants(value: string): Variant[] {
  const variants: Variant[] = [{ name: "raw", text: value }];
  const bytes: Buffer = utf8Bytes(value);
  for (let offset: number = 0; offset < 3; offset++) {
    const groups: number = Math.floor((bytes.length - offset) / 3);
    if (groups < 2) continue;
    const core: string = bytes.subarray(offset, offset + 3 * groups).toString("base64");
    variants.push({ name: `base64 core offset ${offset}`, text: core },
      { name: `base64url core offset ${offset}`, text: core.replaceAll("+", "-").replaceAll("/", "_") });
  }
  const uri: string = encodeURIComponent(value);
  const strict: string = Array.from(uri, (c: string): string =>
    "!'()*".includes(c) ? `%${c.charCodeAt(0).toString(16).toUpperCase()}` : c).join("");
  for (const [name, text] of [["URL", uri], ["strict URL", strict]] as [string, string][]) {
    variants.push({ name, text },
      { name: `${name} lowercase hex`, text: text.replace(/%[\da-f]{2}/gi, (hex: string): string => hex.toLowerCase()) },
      { name: `${name} plus for space`, text: text.replaceAll("%20", "+") });
  }
  const json: string = JSON.stringify(value).slice(1, -1);
  variants.push({ name: "JSON as-is", text: json }, { name: "Python ASCII JSON", text: asciiJson(value) },
    { name: "JSON escaped slash", text: json.replaceAll("/", "\\/") },
    { name: "bash -x single quote", text: value.split("'").join("'\\''") });
  return variants;
}

describe("whole-input oracle and buildPatterns", () => {
  test("reference uses non-overlapping leftmost-longest and literal replacement markers", () => {
    expect(referenceRedact("ababa!", ["ab", "aba", "ba"], "$&$1")).toEqual({ out: "$&$1$&$1!", count: 2 });
    expect(referenceRedact("aaaabaaaab", ["aaaab"], MARKER)).toEqual({ out: MARKER.repeat(2), count: 2 });
    expect(asciiJson("é😀\x7f")).toBe("\\u00e9\\ud83d\\ude00\\u007f");
  });

  test("0–3 UTF-8 bytes give no patterns; two é characters give patterns at four bytes", () => {
    const failures: Failure[] = [];
    for (const value of ["", "a", "ab", "abc", "é", "€", "aé"]) {
      const actual: string[] = buildPatterns(value);
      if (actual.length !== 0) failures.push({ value, input: utf8Bytes(value), boundaries: [],
        expected: "[]", actual: JSON.stringify(actual) });
    }
    assertFailures(failures);
    expect(buildPatterns("éé")).toContain(latin1("éé"));
  });

  test("all listed encodings exist for regex, shell, URL, JSON, Unicode and DEL characters", () => {
    const value: string = 'R.^$&$1[]{}()|?*!"\\\'% /+=é€😀\x7fZ';
    const patterns: string[] = buildPatterns(value);
    const failures: Failure[] = [];
    for (const variant of expectedVariants(value)) {
      if (!patterns.includes(latin1(variant.text))) failures.push({ value, input: utf8Bytes(variant.text),
        boundaries: [], expected: latin1(variant.text), actual: "pattern absent", note: variant.name });
    }
    assertFailures(failures);
  });
});

describe("chunking invariance", () => {
  const values: string[] = ["Q7!z", "aaaab", "abababab", 'R.^$&$1[]{}()|?*!"\\\'% /+=Z', "é€😀Z"];
  for (const value of values) {
    test(`${JSON.stringify(value)}: every split, including inside UTF-8, and byte chunks match reference`, () => {
      allSplits(value, utf8Bytes(value), buildPatterns(value));
    });
    test(`${JSON.stringify(value)}: back-to-back occurrences yield two markers at every split`, () => {
      allSplits(value, utf8Bytes(value + value), buildPatterns(value), { out: MARKER.repeat(2), count: 2 });
    });
  }

  const special: string = 'R.^$&$1[]{}()|?*!"\\\'% /+=é€😀\x7fZ';
  for (const variant of expectedVariants(special)) {
    test(`${variant.name}: every split and byte chunks match whole-input reference`, () => {
      allSplits(special, utf8Bytes(variant.text), buildPatterns(special));
    });
  }

  for (const value of ["éé", "é€😀\x7fZ"]) {
    test(`${JSON.stringify(value)}: Python JSON ASCII escapes match at every split`, () => {
      allSplits(value, utf8Bytes(asciiJson(value)), buildPatterns(value), { out: MARKER, count: 1 });
    });
  }

  const prefixes: { value: string; longer: string; label: string }[] = [
    { value: "abc'", longer: "abc'\\''", label: "' : bash -x" },
    { value: "abc\\", longer: "abc\\\\", label: "backslash: JSON" },
    { value: "abc%", longer: "abc%25", label: "%: URL" },
  ];
  for (const { value, longer, label } of prefixes) {
    test(`value ending in ${label} form split after raw value still yields one marker`, () => {
      const patterns: string[] = buildPatterns(value);
      expect(patterns).toContain(latin1(longer));
      expect(referenceRedact(latin1(longer), patterns, MARKER)).toEqual({ out: MARKER, count: 1 });
      allSplits(value, utf8Bytes(longer), patterns, { out: MARKER, count: 1 });
    });
  }
});

describe("Basic auth and base64url", () => {
  const value: string = "Probe-é😀/+=-token!";
  for (let length: number = 0; length <= 5; length++) {
    for (const newline of [false, true]) {
      test(`Basic auth prefix length ${length}, ${newline ? "echo newline" : "printf without newline"}: all splits`, () => {
        const prefix: string = "user:".slice(0, length);
        const encoded: string = utf8Bytes(prefix + value + (newline ? "\n" : "")).toString("base64");
        const patterns: string[] = buildPatterns(value);
        const expected: Reference = referenceRedact(encoded, patterns, MARKER);
        expect(expected.count, "each alignment must contain at least one independently encoded core").toBeGreaterThan(0);
        allSplits(value, utf8Bytes(encoded), patterns, expected);
      });
    }
  }
  // Cores are kept only if >= 8 chars, so every alignment is covered only for values of 8+ bytes.
  // A 4–7 byte value is missed in base64 at some alignments: a documented limit, not tested here.
  test("Basic auth is caught at every prefix length 0..5 for values of 8..12 bytes", () => {
    const uncaught: string[] = [];
    for (let length: number = 8; length <= 12; length++) {
      const value: string = "Kz7#wQ9!pL".slice(0, length);
      const patterns: string[] = buildPatterns(value);
      for (let prefixLength: number = 0; prefixLength <= 5; prefixLength++) {
        const encoded: string = utf8Bytes("user:".slice(0, prefixLength) + value).toString("base64");
        if (referenceRedact(encoded, patterns, MARKER).count === 0) uncaught.push(`len=${length},prefix=${prefixLength}`);
      }
    }
    expect(uncaught, `base64(prefix + value) with no redaction at all: ${uncaught.join(" ")}`).toEqual([]);
  });

  test("base64url with both changed alphabet characters matches at every split", () => {
    const value: string = "😀\uffffProbe-token";
    const ordinary: string = utf8Bytes(value).toString("base64");
    expect(ordinary).toContain("+");
    expect(ordinary).toContain("/");
    const encoded: string = utf8Bytes(value).toString("base64url");
    const patterns: string[] = buildPatterns(value);
    expect(referenceRedact(encoded, patterns, MARKER).count).toBeGreaterThan(0);
    allSplits(value, utf8Bytes(encoded), patterns);
  });
});

describe('format "full"', () => {
  for (const value of ["short\n" + "L".repeat(20) + "\nX", "S".repeat(20) + "\nab"]) {
    test(`${JSON.stringify(value)}: whole multiline occurrence yields exactly one marker at every split`, () => {
      allSplits(value, utf8Bytes(value), buildPatterns(value, "full"), { out: MARKER, count: 1 });
    });
    test(`${JSON.stringify(value)}: no short line leaks when input is exactly the full value`, () => {
      const failures: Failure[] = [];
      const patterns: string[] = buildPatterns(value, "full");
      const input: Buffer = utf8Bytes(value);
      const shortLines: string[] = value.split(/\r?\n/).filter((line: string): boolean => line.length > 0 && line.length < 16);
      for (const boundaries of chunkings(input.length)) {
        const actual: Run = runChunked(new StreamRedactor(patterns, MARKER), input, boundaries);
        const leaks: string[] = shortLines.filter((line: string): boolean => actual.out.includes(utf8Bytes(line)));
        if (leaks.length > 0) failures.push({ value, input, boundaries, expected: MARKER,
          actual: actual.out.toString("latin1"), note: `LEAK: short lines ${JSON.stringify(leaks)}` });
      }
      assertFailures(failures);
    });
    test(`${JSON.stringify(value)}: base64 of full value obeys leftmost-longest reference at every split`, () => {
      allSplits(value, utf8Bytes(utf8Bytes(value).toString("base64")), buildPatterns(value, "full"));
    });
    test(`${JSON.stringify(value)}: seeded random binary with inserted full-format patterns matches reference`, () => {
      seededProperty(value, buildPatterns(value, "full"), 0xf011);
    });
  }
});

describe("marker interaction: test the conflicting invariants independently", () => {
  test("marker containing $&, $1, $' and \\ is emitted literally (no replace() semantics)", () => {
    const marker: string = "<$&|$1|$'|\\>";
    const value: string = "Probe-$&-$1-token";
    const input: Buffer = utf8Bytes(`a ${value} b ${value}`);
    const redactor: Redactor = new StreamRedactor(buildPatterns(value), marker);
    const out: string = Buffer.concat([redactor.push(input.subarray(0, 9)), redactor.push(input.subarray(9)), redactor.end()]).toString("latin1");
    expect(out).toBe(`a ${marker} b ${marker}`);
    expect(redactor.count).toBe(2);
  });

  for (const { value, input } of [
    { value: "cred", input: "cred" },
    { value: "red:t", input: "red:t" },
    { value: "t]ab", input: "t]abab" },
  ]) {
    test(`${JSON.stringify(value)}: invariant 1 preserves reference output even if marker reforms a pattern`, () => {
      allSplits(value, utf8Bytes(input), buildPatterns(value));
    });
    // The marker itself can spell the value (a value that is a piece of "[cred:<name>]"); that is
    // the name, not leaked input. What must hold: no input byte of the value survives outside markers.
    test(`${JSON.stringify(value)}: with the markers removed, the output contains no pattern`, () => {
      const patterns: string[] = buildPatterns(value);
      const failures: Failure[] = [];
      for (const boundaries of chunkings(utf8Bytes(input).length)) {
        const actual: Run = runChunked(new StreamRedactor(patterns, MARKER), utf8Bytes(input), boundaries);
        const rest: string = actual.out.toString("latin1").split(MARKER).join("");
        const found: string | undefined = patterns.find((pattern: string): boolean => rest.includes(pattern));
        if (found !== undefined) failures.push({ value, input: utf8Bytes(input), boundaries,
          expected: `no occurrence of ${JSON.stringify(found)} outside markers`, actual: actual.out.toString("latin1"),
          note: "input bytes of the value survived outside a marker" });
      }
      assertFailures(failures);
    });
  }
});

// Random binary with random patterns spliced in at random positions, random chunkings, against the
// whole-input reference. Increasing payload sizes make the reported smallest failure reproducible.
function seededProperty(value: string, patterns: string[], seed: number): void {
  const random: () => number = mulberry32(seed);
  const failures: Failure[] = [];
  for (let trial: number = 0; trial < 160; trial++) {
    const bytes: number[] = Array.from({ length: trial }, (): number => Math.floor(random() * 256));
    const insertions: number = 1 + Math.floor(random() * 4);
    for (let n: number = 0; n < insertions; n++) {
      const position: number = Math.floor(random() * (bytes.length + 1));
      const pattern: string = patterns[Math.floor(random() * patterns.length)];
      bytes.splice(position, 0, ...Buffer.from(pattern, "latin1"));
    }
    const input: Buffer = Buffer.from(bytes);
    for (let repeat: number = 0; repeat < 5; repeat++) {
      recordComparison(failures, value, input, randomBoundaries(input.length, random), patterns,
        undefined, seed, `trial=${trial}, chunking=${repeat}`);
    }
  }
  assertFailures(failures);
}

describe("seeded binary properties", () => {
  const values: string[] = ["Q7!z", "aaaab", "abababab", "abc'", "abc\\", "abc%", "é€😀Z",
    'R.^$&$1[]{}()|?*!"\\\'% /+=é€😀\x7fZ'];
  for (const value of values) {
    test(`${JSON.stringify(value)}: random binary with random inserted patterns matches reference`, () => {
      seededProperty(value, buildPatterns(value), SEED);
    });
  }

  test("pattern-free random binary passes byte-identical under seeded chunkings", () => {
    const value: string = "Probe-binary-secret-Q7!z";
    const patterns: string[] = buildPatterns(value);
    const random: () => number = mulberry32(SEED);
    const failures: Failure[] = [];
    for (let trial: number = 0; trial < 128; trial++) {
      const input: Buffer = Buffer.from(Array.from({ length: trial * 3 }, (): number => Math.floor(random() * 256)));
      expect(patterns.some((pattern: string): boolean => input.includes(Buffer.from(pattern, "latin1")))).toBe(false);
      recordComparison(failures, value, input, randomBoundaries(input.length, random), patterns,
        { out: input.toString("latin1"), count: 0 }, SEED);
    }
    assertFailures(failures);
  });

  test("invariant 2: after each push all bytes before the earliest possible pattern start are emitted", () => {
    const value: string = "Q7!z-probe";
    const patterns: string[] = buildPatterns(value);
    const random: () => number = mulberry32(SEED);
    const failures: Failure[] = [];
    for (let trial: number = 0; trial < 100; trial++) {
      const parts: Buffer[] = [];
      for (let n: number = 0; n <= trial; n++) {
        // NUL rules out every full pattern; partial prefixes and false starts are deliberate.
        const pattern: string = patterns[Math.floor(random() * patterns.length)];
        const prefixLength: number = Math.floor(random() * pattern.length);
        parts.push(Buffer.from([Math.floor(random() * 256), 0]), Buffer.from(pattern.slice(0, prefixLength), "latin1"), Buffer.from([0]));
      }
      const input: Buffer = Buffer.concat(parts);
      expect(patterns.some((pattern: string): boolean => input.includes(Buffer.from(pattern, "latin1")))).toBe(false);
      const boundaries: number[] = [...randomBoundaries(input.length, random), input.length];
      const redactor: Redactor = new StreamRedactor(patterns, MARKER);
      let emitted: Buffer = Buffer.alloc(0);
      let start: number = 0;
      for (let step: number = 0; step < boundaries.length; step++) {
        const end: number = boundaries[step];
        emitted = Buffer.concat([emitted, redactor.push(input.subarray(start, end))]);
        const seen: string = input.subarray(0, end).toString("latin1");
        let earliest: number = seen.length;
        for (let i: number = 0; i < seen.length; i++) {
          const suffix: string = seen.slice(i);
          if (patterns.some((pattern: string): boolean => suffix.length < pattern.length && pattern.startsWith(suffix))) {
            earliest = i;
            break;
          }
        }
        const expected: string = seen.slice(0, earliest);
        if (emitted.toString("latin1") !== expected) failures.push({ value, input: input.subarray(0, end),
          boundaries: boundaries.slice(0, step + 1), expected, actual: emitted.toString("latin1"),
          seed: SEED, note: `no-delay trial=${trial}, step=${step}, earliest=${earliest}` });
        start = end;
      }
      const ended: Buffer = Buffer.concat([emitted, redactor.end()]);
      if (!ended.equals(input)) failures.push({ value, input, boundaries, expected: input.toString("latin1"),
        actual: ended.toString("latin1"), seed: SEED, note: "end must preserve remaining bytes" });
    }
    assertFailures(failures);
  });
});

describe("idleFlush explicit semantics", () => {
  for (const k of [1, 2, 3]) {
    test(`release ${k} byte(s), then complete a pattern: only released bytes precede one marker`, () => {
      const value: string = "Probe-idle-token";
      const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
      expect(redactor.push(utf8Bytes(value.slice(0, k)))).toEqual(Buffer.alloc(0));
      expect(redactor.waiting).toBe(true);
      expect(redactor.idleFlush()).toEqual(utf8Bytes(value.slice(0, k)));
      expect(redactor.waiting).toBe(false);
      const rest: Buffer = Buffer.concat([redactor.push(utf8Bytes(value.slice(k))), redactor.end()]);
      expect(rest.toString("latin1")).toBe(MARKER);
      expect(redactor.count).toBe(1);
    });
  }

  test("aaaab: releasing aa then pushing aaab emits only aa followed by one marker", () => {
    const value: string = "aaaab";
    const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
    const output: Buffer[] = [redactor.push(utf8Bytes("aa")), redactor.idleFlush(), redactor.push(utf8Bytes("aaab")), redactor.end()];
    const actual: string = Buffer.concat(output).toString("latin1");
    expect(actual, 'value="aaaab" input="aaaaab" boundaries=[2] idleFlush after 2; expected="aa[cred:test]" actual=' + JSON.stringify(actual)).toBe("aa" + MARKER);
    expect(redactor.count).toBe(1);
  });

  test("4+ byte holds cannot be idle-flushed", () => {
    const failures: Failure[] = [];
    const value: string = "Probe-hold-token";
    for (let k: number = 4; k < value.length; k++) {
      const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
      const initial: Buffer = redactor.push(utf8Bytes(value.slice(0, k)));
      const waiting: boolean = redactor.waiting;
      const flushed: Buffer = redactor.idleFlush();
      const actual: string = Buffer.concat([initial, flushed, redactor.push(utf8Bytes(value.slice(k))), redactor.end()]).toString("latin1");
      if (initial.length !== 0 || waiting || flushed.length !== 0 || actual !== MARKER || redactor.count !== 1) {
        failures.push({ value, input: utf8Bytes(value), boundaries: [k], expected: MARKER, actual,
          expectedCount: 1, actualCount: redactor.count, note: `waiting=${waiting}, initial=${JSON.stringify(initial.toString())}, idle=${JSON.stringify(flushed.toString())}` });
      }
    }
    assertFailures(failures);
  });

  test("repeated one-byte idle releases never cumulatively release four bytes of one match", () => {
    const failures: Failure[] = [];
    for (const value of ["Probe-idle-token", "aaaaaaab"]) {
      const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
      const output: Buffer[] = [];
      let released: number = 0;
      for (let step: number = 0; step < 4; step++) {
        const pushed: Buffer = redactor.push(utf8Bytes(value[step]));
        output.push(pushed);
        const waiting: boolean = redactor.waiting;
        const expectedWaiting: boolean = step < 3;
        const flushed: Buffer = redactor.idleFlush();
        released += flushed.length;
        output.push(flushed);
        if (pushed.length !== 0 || waiting !== expectedWaiting || flushed.length !== (step < 3 ? 1 : 0) || released >= 4) {
          failures.push({ value, input: utf8Bytes(value.slice(0, step + 1)),
            boundaries: Array.from({ length: step + 1 }, (_: unknown, i: number): number => i + 1),
            expected: value.slice(0, Math.min(step + 1, 3)), actual: Buffer.concat(output).toString("latin1"),
            note: `idle after every push; expected waiting=${expectedWaiting}, actual waiting=${waiting}; cumulative released=${released}; hold plus released=${step + 1}` });
        }
      }
      output.push(redactor.push(utf8Bytes(value.slice(4))), redactor.end());
      const actual: string = Buffer.concat(output).toString("latin1");
      if (actual !== value.slice(0, 3) + MARKER || redactor.count !== 1) failures.push({ value, input: utf8Bytes(value),
        boundaries: [1, 2, 3, 4], expected: value.slice(0, 3) + MARKER, actual,
        expectedCount: 1, actualCount: redactor.count, note: "idle after first four pushes" });
    }
    assertFailures(failures);
  });

  test("released 2 bytes plus a 3-byte continuation (5 >= 4) is not waiting and is not released", () => {
    const value: string = "Probe-idle-token";
    const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
    expect(redactor.push(utf8Bytes("Pr")).length).toBe(0);
    expect(redactor.idleFlush().toString("latin1")).toBe("Pr");
    expect(redactor.push(utf8Bytes("obe")).length).toBe(0);
    expect(redactor.waiting).toBe(false);
    expect(redactor.idleFlush().length).toBe(0);
    const rest: string = Buffer.concat([redactor.push(utf8Bytes(value.slice(5))), redactor.end()]).toString("latin1");
    expect(rest).toBe(MARKER);
    expect(redactor.count).toBe(1);
  });

  test("nothing held: waiting is false and idleFlush returns an empty Buffer", () => {
    const redactor: Redactor = new StreamRedactor(buildPatterns("Probe-idle-token"), MARKER);
    expect(redactor.push(utf8Bytes("plain output\n")).toString("latin1")).toBe("plain output\n");
    expect(redactor.waiting).toBe(false);
    const flushed: Buffer = redactor.idleFlush();
    expect(Buffer.isBuffer(flushed)).toBe(true);
    expect(flushed.length).toBe(0);
  });

  test("three released bytes proven false are preserved before a subsequent real occurrence", () => {
    const value: string = "Probe-idle-token";
    const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
    const output: Buffer[] = [redactor.push(utf8Bytes("Pro"))];
    expect(redactor.waiting).toBe(true);
    output.push(redactor.idleFlush(), redactor.push(utf8Bytes("!" + value)), redactor.end());
    expect(Buffer.concat(output).toString("latin1")).toBe("Pro!" + MARKER);
    expect(redactor.count).toBe(1);
  });
});

test("50 MB in 64 KB chunks completes below 10,000 ms with byte-identical output", () => {
  const value: string = "Probe-perf-é😀-secret-Q7!z";
  const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
  const totalBytes: number = 50_000_000;
  const chunkSize: number = 64 * 1024;
  // A varied binary workload, guaranteed not to contain a pattern; check every returned byte.
  const source: Buffer = Buffer.alloc(chunkSize);
  for (let i: number = 0; i < source.length; i++) source[i] = i % 256;
  let emitted: number = 0;
  let identical: boolean = true;
  const started: number = performance.now();
  for (let offset: number = 0; offset < totalBytes; offset += chunkSize) {
    const input: Buffer = source.subarray(0, Math.min(chunkSize, totalBytes - offset));
    const out: Buffer = redactor.push(input);
    for (let i: number = 0; i < out.length; i++) if (out[i] !== (emitted + i) % 256) identical = false;
    emitted += out.length;
  }
  const tail: Buffer = redactor.end();
  for (let i: number = 0; i < tail.length; i++) if (tail[i] !== (emitted + i) % 256) identical = false;
  emitted += tail.length;
  const elapsedMs: number = performance.now() - started;
  console.log(`50 MB timing: ${elapsedMs.toFixed(2)} ms; ${(totalBytes / 1_000_000 / (elapsedMs / 1000)).toFixed(2)} MB/s`);
  expect(identical).toBe(true);
  expect(emitted).toBe(totalBytes);
  expect(redactor.count).toBe(0);
  expect(elapsedMs).toBeLessThan(10_000);
}, 60_000);

const PERF_TOTAL: number = 50_000_000;
const PERF_CHUNK: number = 64 * 1024;

// Pushes `input` in 64 KB chunks, times only push()/end(), and compares to `expected` byte for byte.
function timedRun(label: string, value: string, input: Buffer, expected: Buffer, expectedCount: number): void {
  const redactor: Redactor = new StreamRedactor(buildPatterns(value), MARKER);
  const outputs: Buffer[] = [];
  const started: number = performance.now();
  for (let offset: number = 0; offset < input.length; offset += PERF_CHUNK) {
    outputs.push(redactor.push(input.subarray(offset, offset + PERF_CHUNK)));
  }
  outputs.push(redactor.end());
  const elapsedMs: number = performance.now() - started;
  console.log(`50 MB ${label}: ${elapsedMs.toFixed(2)} ms; ${(input.length / 1_000_000 / (elapsedMs / 1000)).toFixed(2)} MB/s; ${redactor.count} replacements`);
  const output: Buffer = Buffer.concat(outputs);
  expect(redactor.count).toBe(expectedCount);
  expect(output.length).toBe(expected.length);
  expect(output.equals(expected)).toBe(true);
  expect(elapsedMs).toBeLessThan(10_000);
}

test("50 MB seeded random binary with an occurrence every ~4 KB: exact output, below 10,000 ms", () => {
  const value: string = "Probe-perf-é😀-secret-Q7!z";
  const patterns: Buffer[] = buildPatterns(value).map((p: string): Buffer => Buffer.from(p, "latin1"));
  const random: () => number = mulberry32(0x5eed);
  const pool: Buffer = Buffer.from(Array.from({ length: 1 << 20 }, (): number => Math.floor(random() * 256)));
  for (const p of patterns) expect(pool.includes(p)).toBe(false);
  const inputParts: Buffer[] = [];
  const expectedParts: Buffer[] = [];
  const marker: Buffer = Buffer.from(MARKER, "latin1");
  let size: number = 0;
  let occurrences: number = 0;
  while (size < PERF_TOTAL) {
    const fillerLength: number = Math.floor(random() * 8192);
    const start: number = Math.floor(random() * (pool.length - fillerLength));
    const filler: Buffer = pool.subarray(start, start + fillerLength);
    const pattern: Buffer = patterns[occurrences % patterns.length];
    inputParts.push(filler, pattern);
    expectedParts.push(filler, marker);
    size += filler.length + pattern.length;
    occurrences++;
  }
  timedRun("random+occurrences", value, Buffer.concat(inputParts), Buffer.concat(expectedParts), occurrences);
}, 120_000);

test("50 MB of back-to-back near-miss prefixes (worst case for holding): byte-identical, below 10,000 ms", () => {
  const value: string = "Probe-perf-é😀-secret-Q7!z";
  const raw: Buffer = utf8Bytes(value);
  const nearMiss: Buffer = Buffer.concat([raw.subarray(0, raw.length - 1), Buffer.from([0])]);
  const input: Buffer = Buffer.alloc(PERF_TOTAL);
  for (let offset: number = 0; offset < input.length; offset += nearMiss.length) nearMiss.copy(input, offset);
  timedRun("near-miss prefixes", value, input, input, 0);
}, 120_000);

test("50 MB of the value back to back (every byte inside a match): exact output, below 10,000 ms", () => {
  const value: string = "Probe-perf-é😀-secret-Q7!z";
  const raw: Buffer = utf8Bytes(value);
  const copies: number = Math.floor(PERF_TOTAL / raw.length);
  const input: Buffer = Buffer.alloc(copies * raw.length);
  for (let i: number = 0; i < copies; i++) raw.copy(input, i * raw.length);
  timedRun("back-to-back matches", value, input, Buffer.from(MARKER.repeat(copies), "latin1"), copies);
}, 120_000);
