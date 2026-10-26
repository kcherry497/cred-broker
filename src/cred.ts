#!/usr/bin/env bun
// cred — a local credential broker for AI coding agents.
//
// THE PROBLEM
// Whatever an agent sees is captured: it enters the context window, is sent to the model
// provider, is written to the session transcript, and is often copied on into memory or search
// tools. A secret that is printed once is in all of those places for good. Encryption at rest
// does not help: the leak happens at USE time. The only design that keeps a secret out of the
// transcript is one where the model never receives it.
//
// THE MODEL: ssh-agent's trick, generalised.
//   `ssh host` is safe not because the key is encrypted, but because the key never enters the
//   conversation: the reference is not sensitive and the proof happens in a process the model
//   cannot see. `cred exec github -- <cmd>` does the same for bearer secrets: decrypt from
//   pass, inject into one child process's environment, stream back only the child's output,
//   with the value filtered out of it.
//
// WHAT THIS DELIBERATELY DOES NOT HAVE
//   There is no `get`, no `show`, no `cat`. The absence is the feature: every printing path
//   is the bug.
//
// HONEST LIMITS — read before trusting this
//   * The child's stdout and stderr are filtered: the value, and its base64 /
//     base64url (at any byte offset, so Basic auth too), URL, JSON and shell-quoted
//     forms, come out as [cred:<name>]. Base64 is caught at every offset only for
//     values of 8+ bytes, and values under 4 bytes are not filtered at all (the
//     broker says so on stderr). Copies transformed any other way (`| rev`,
//     hex, gzip, base64 wrapped across lines) are not caught, and neither is
//     anything the child sends to the network or writes to a file.
//   * Up to 3 bytes of a value can show if the child prints them and then pauses
//     for 150 ms (a prompt with no newline must not hang); the rest is still filtered.
//   * The broker blocks the obvious env dumpers, but this is a guardrail against
//     ACCIDENT, not a sandbox against a determined process. A child that wants to
//     leak its own env can, and anything running as your user can reach gpg-agent.
//   * The real guarantee is narrower and more valuable than "secrets are safe":
//     nobody has to paste a credential into an agent chat, and no session has a
//     reason to print one.

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync,
  renameSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { constants as osConstants, homedir } from "node:os";
import { dirname, join } from "node:path";
import { Transform } from "node:stream";
import YAML from "yaml";

// Where things live. Each moves with an env var; the defaults follow XDG.
const CONFIG_HOME = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
const STATE_HOME = process.env.XDG_STATE_HOME || join(homedir(), ".local", "state");
const MANIFEST_PATH = process.env.CRED_MANIFEST || join(CONFIG_HOME, "cred-broker", "manifest.yaml");
const STATE_DIR = process.env.CRED_STATE_DIR || join(STATE_HOME, "cred-broker");
const AUDIT_DIR = process.env.CRED_AUDIT_DIR || join(STATE_DIR, "audit");
// A store just for brokered credentials keeps an unlock from opening everything else in pass.
const PASS_STORE = process.env.CRED_STORE_DIR || process.env.PASSWORD_STORE_DIR || join(homedir(), ".password-store");
const PASS_ENV = { ...process.env, PASSWORD_STORE_DIR: PASS_STORE };
const UNLOCK_STATE_PATH = join(STATE_DIR, "unlock-state.json");
const GNUPG_HOME = process.env.GNUPGHOME || join(homedir(), ".gnupg");
// How the user runs this tool, for messages: the script actually invoked (a wrapper, if any).
const SELF = `bun ${process.argv[1] ?? import.meta.path}`;
const GPG_AGENT_CONF = join(GNUPG_HOME, "gpg-agent.conf");
const MAX_UNLOCK_HOURS = 12;
// An agent's runs carry its session ID (CRED_SESSION_ID for any agent; Claude Code sets its own).
// Without one, a person ran this from their own shell, so record who: $USER, $LOGNAME, then the
// account database.
const SESSION = process.env.CRED_SESSION_ID || process.env.CLAUDE_CODE_SESSION_ID || process.env.CLAUDE_SESSION_ID
  || process.env.USER || process.env.LOGNAME || loginName();

// Bun's os.userInfo().username only reads $USER and says "unknown" without it; id(1) asks NSS.
function loginName(): string {
  const r = spawnSync("id", ["-un"], { encoding: "utf8" });
  return (r.status === 0 && r.stdout.trim()) || `uid:${process.getuid?.() ?? "?"}`;
}

interface Entry {
  describes: string;      // what it maps to, in human terms — safe for context
  pass_path: string;      // location in the password store
  env: string;            // env var name injected into the child
  risk?: "low" | "medium" | "high";
  format?: "line" | "full"; // line (default): first line, pass convention; full: the whole entry (keys, JSON)
  note?: string;
}
type Manifest = Record<string, Entry>;

// Commands that would dump the injected variable straight back into the
// transcript. Not exhaustive and not a security boundary — a tripwire for the
// obvious accident.
const DUMPERS = /^(env|printenv|set|export|declare)$/;

// ───────────────────────── audit ─────────────────────────

function auditPath(): string {
  const day = new Date().toISOString().slice(0, 10);   // UTC, for both the folder and the file
  const dir = join(AUDIT_DIR, day.slice(0, 4), day.slice(5, 7));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return join(dir, `cred-${day.replace(/-/g, "")}.jsonl`);
}

// Never logs the value. Logs that access happened, for what, by whom.
function audit(event: Record<string, unknown>): void {
  appendFileSync(auditPath(), JSON.stringify({
    timestamp: new Date().toISOString(),
    session: SESSION,
    ...event,
  }) + "\n", "utf8");
}

// ───────────────────────── manifest ─────────────────────────

// Only `_`-free top-level keys are brokered credentials. `_tool_native` and
// `_public` are documentation for the reader (and for the session): things that
// need no broker because the tool already owns the secret, and things that are
// not secret at all. Keeping them in one file means one place answers "what can
// I use and how" — but only these entries have a value in `pass`.
function loadManifest(): Manifest {
  if (!existsSync(MANIFEST_PATH)) return {};
  const raw = (YAML.parse(readFileSync(MANIFEST_PATH, "utf8")) ?? {}) as Record<string, unknown>;
  const out: Manifest = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k.startsWith("_")) continue;
    const e = v as Entry;
    if (e && typeof e === "object" && e.pass_path && e.env) out[k] = e;
  }
  return out;
}

function resolve(name: string): Entry {
  const m = loadManifest();
  const e = m[name];
  if (!e) {
    const known = Object.keys(m).join(", ") || "(manifest empty)";
    throw new Error(`unknown credential '${name}'. Known: ${known}`);
  }
  if (!existsSync(join(PASS_STORE, e.pass_path + ".gpg"))) {
    throw new Error(
      `'${name}' is in the manifest but not in the store.\n` +
      `  The user runs, in their own terminal:  ${SELF} set ${name}\n` +
      `  (it prompts on their tty; the value never passes through the agent)`);
  }
  return e;
}

// ───────────────────────── redaction ─────────────────────────

// A value shorter than this is not filtered: a 3-byte pattern would shred ordinary output.
const MIN_REDACT = 4;
// Base64 pieces shorter than this are skipped for the same reason.
const MIN_ENCODED = 8;
// With `format: full`, each line at least this long is also matched on its own.
const MIN_LINE = 16;
// Held bytes shorter than MIN_HOLD are released after this much silence, so a prompt that ends
// in what looks like the start of the value cannot hang. Longer holds wait for more output.
const IDLE_FLUSH_MS = 150;
const MIN_HOLD = 4;

// Patterns are matched against output read as latin1 (one char per byte), so binary passes
// through unchanged; each pattern is therefore the latin1 view of its UTF-8 bytes.
const bytesOf = (s: string) => Buffer.from(s, "utf8").toString("latin1");

// The base64 groups that depend only on the value, for each of the three byte offsets it can
// start at inside a longer encoded string (Basic auth is base64("user:" + value)). Groups that
// share bits with neighbouring bytes differ from case to case, so they are left out.
function base64Cores(bytes: Buffer): string[] {
  const cores: string[] = [];
  for (const skip of [0, 1, 2]) {
    const n = Math.floor((bytes.length - skip) / 3) * 3;
    if (n > 0) cores.push(bytes.subarray(skip, skip + n).toString("base64"));
  }
  return cores;
}

// The value and the forms a command most often prints it in.
export function buildPatterns(value: string, format: "line" | "full" = "line"): string[] {
  const out = new Set<string>();
  const add = (s: string) => { if (Buffer.byteLength(s) >= MIN_REDACT) out.add(bytesOf(s)); };
  const variants = (v: string) => {
    if (Buffer.byteLength(v) < MIN_REDACT) return;
    add(v);
    for (const core of base64Cores(Buffer.from(v, "utf8"))) {
      if (core.length < MIN_ENCODED) continue;
      add(core);
      add(core.replace(/\+/g, "-").replace(/\//g, "_"));
    }
    const uri = encodeURIComponent(v);
    const strict = uri.replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
    for (const u of [uri, strict]) {
      add(u);
      add(u.replace(/%[0-9A-F]{2}/g, (h) => h.toLowerCase()));
      add(u.replace(/%20/g, "+"));
    }
    const json = JSON.stringify(v).slice(1, -1);
    add(json);
    add(json.replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")));
    add(json.replace(/\//g, "\\/"));
    if (v.includes("'")) add(v.replace(/'/g, "'\\''"));   // how `bash -x` and `set -x` quote it
  };
  variants(value);
  if (format === "full") for (const line of value.split(/\r?\n/)) if (line.length >= MIN_LINE) variants(line);
  return [...out];
}

// Replaces every pattern in a byte stream with `marker`, one chunk at a time. Bytes that could be
// the start of a pattern are held until the next chunk shows whether they are; every other byte is
// passed on unchanged and at once.
export class StreamRedactor {
  count = 0;
  private held = "";          // not yet emitted
  private look = "";          // emitted since the last marker; a pattern can start in released bytes
  private lookPrefix = 0;     // how much of `look` is the start of a pattern still in progress
  private readonly maxLen: number;
  private readonly firsts: Set<string>;

  constructor(private readonly patterns: string[], private readonly marker: string) {
    this.maxLen = Math.max(0, ...patterns.map((p) => p.length));
    this.firsts = new Set(patterns.map((p) => p[0]));
  }

  push(chunk: Buffer): Buffer {
    return Buffer.from(this.scan(chunk.toString("latin1"), false), "latin1");
  }

  end(): Buffer {
    return Buffer.from(this.scan("", true), "latin1");
  }

  // True when the only thing held back is a few bytes that idleFlush() would release.
  get waiting(): boolean {
    return this.held.length > 0 && this.held.length + this.lookPrefix < MIN_HOLD;
  }

  // Releases a short hold after silence. If those bytes were the start of the value, the rest is
  // still caught, because they stay in `look`.
  idleFlush(): Buffer {
    if (!this.waiting) return Buffer.alloc(0);
    const out = this.held;
    this.held = "";
    this.remember(this.look + out);
    return Buffer.from(out, "latin1");
  }

  private remember(s: string) {
    this.look = this.maxLen > 1 ? s.slice(-(this.maxLen - 1)) : "";
  }

  private scan(data: string, final: boolean): string {
    if (!this.patterns.length) return data;
    const base = this.look.length;            // s[0, base) is already out
    const s = this.look + this.held + data;
    const hits: [number, number][] = [];
    for (const p of this.patterns) {
      for (let i = s.indexOf(p); i !== -1; i = s.indexOf(p, i + 1)) hits.push([i, i + p.length]);
    }
    hits.sort((a, b) => a[0] - b[0] || b[1] - a[1]);   // leftmost, then longest
    // Positions whose remaining text is a proper prefix of some pattern: a match may still be arriving there.
    const pending: number[] = [];
    if (!final) {
      for (let i = Math.max(0, s.length - this.maxLen + 1); i < s.length; i++) {
        if (!this.firsts.has(s[i])) continue;
        const rest = s.slice(i);
        if (this.patterns.some((p) => p.length > rest.length && p.startsWith(rest))) pending.push(i);
      }
    }
    let out = "", cur = base, taken = 0, lastEnd = -1, pi = 0;
    for (const [a, b] of hits) {
      if (a < taken || b <= base) continue;
      while (pi < pending.length && pending[pi] < taken) pi++;
      // A longer match starting here, or any match starting earlier, could still win: wait for it.
      if (pi < pending.length && pending[pi] <= a) break;
      out += s.slice(cur, Math.max(a, cur)) + this.marker;
      cur = taken = lastEnd = b;
      this.count++;
    }
    if (final) {
      out += s.slice(cur);
      this.held = this.look = "";
      this.lookPrefix = 0;
      return out;
    }
    while (pi < pending.length && pending[pi] < taken) pi++;
    const hold = pi < pending.length ? pending[pi] : s.length;
    const emitTo = Math.max(hold, cur);
    out += s.slice(cur, emitTo);
    this.held = s.slice(emitTo);
    this.lookPrefix = hold < cur ? cur - hold : 0;
    this.remember(s.slice(lastEnd >= 0 ? lastEnd : 0, emitTo));
    return out;
  }
}

function redactStream(r: StreamRedactor): Transform {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const t = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      clearTimeout(timer);
      const out = r.push(chunk);
      if (out.length) this.push(out);
      if (r.waiting) {
        timer = setTimeout(() => {
          const b = r.idleFlush();
          if (b.length) t.push(b);
        }, IDLE_FLUSH_MS);
      }
      cb();
    },
    flush(cb) {
      clearTimeout(timer);
      const out = r.end();
      if (out.length) this.push(out);
      cb();
    },
  });
  return t;
}

function redactText(text: string, patterns: string[], marker: string): string {
  const r = new StreamRedactor(patterns, marker);
  return Buffer.concat([r.push(Buffer.from(text, "utf8")), r.end()]).toString("utf8");
}

// ───────────────────────── unlock state ─────────────────────────

type TtlKey = "default-cache-ttl" | "max-cache-ttl";
const TTL_KEYS: TtlKey[] = ["default-cache-ttl", "max-cache-ttl"];
type Ttl = Record<TtlKey, string | null>;
const NO_TTL: Ttl = { "default-cache-ttl": null, "max-cache-ttl": null };
// Precedes the TTL lines `unlock` writes, so `lock` knows they are ours to undo.
const TTL_MARK = "# cred-managed: written by cred unlock, restored by cred lock";
const isMark = (l: string) => l === TTL_MARK;

interface UnlockState {
  unlocked_at: string;
  expires_at: string;
  hours: number;
  by_session: string;
  window_id: string;      // the expiry relock acts only if this window is still the current one
  ttl_restore: Ttl;       // the user's own TTL lines from before the first unlock (null = absent)
}

function readUnlockState(): UnlockState | null {
  if (!existsSync(UNLOCK_STATE_PATH)) return null;
  try {
    return JSON.parse(readFileSync(UNLOCK_STATE_PATH, "utf8")) as UnlockState;
  } catch {
    return null;
  }
}

function writeUnlockState(s: UnlockState): void {
  const dir = dirname(UNLOCK_STATE_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(UNLOCK_STATE_PATH, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
}

function clearUnlockState(): void {
  if (existsSync(UNLOCK_STATE_PATH)) unlinkSync(UNLOCK_STATE_PATH);
}

function readAgentConf(): { lines: string[]; managed: boolean; ttl: Ttl } {
  const lines = existsSync(GPG_AGENT_CONF) ? readFileSync(GPG_AGENT_CONF, "utf8").split("\n") : [];
  const ttl: Ttl = { ...NO_TTL };
  for (const l of lines) {
    const m = l.match(/^\s*(default-cache-ttl|max-cache-ttl)\s+(\S+)/);
    if (m) ttl[m[1] as TtlKey] = m[2];
  }
  return { lines, managed: lines.some(isMark), ttl };
}

// Writes through a symlink, keeps the file's mode, and never leaves a half-written file.
function writeAtomic(path: string, data: string): void {
  const target = existsSync(path) && lstatSync(path).isSymbolicLink() ? realpathSync(path) : path;
  const mode = existsSync(target) ? statSync(target).mode & 0o777 : 0o600;
  if (!existsSync(dirname(target))) mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const tmp = `${target}.cred-${process.pid}`;
  writeFileSync(tmp, data, { mode });
  renameSync(tmp, target);
}

// Replaces gpg-agent.conf's TTL lines with `ttl`: our marked pair while a window is open, the
// user's own lines (or none, meaning gpg-agent's defaults) once it closes. Other lines are kept.
function setAgentTtl(ttl: Ttl, managed: boolean): void {
  const kept = readAgentConf().lines
    .filter((l) => !isMark(l) && !/^\s*(default-cache-ttl|max-cache-ttl)\b/.test(l));
  while (kept.length && kept[kept.length - 1] === "") kept.pop();
  const set = TTL_KEYS.filter((k) => ttl[k] !== null).map((k) => `${k} ${ttl[k]}`);
  const out = [...kept, ...(managed && set.length ? [TTL_MARK] : []), ...set];
  writeAtomic(GPG_AGENT_CONF, out.length ? out.join("\n") + "\n" : "");
}

function run(cmd: string, args: string[]): Promise<number> {
  return new Promise((res) => {
    const p = spawn(cmd, args, { stdio: "pipe" });
    p.on("close", (c) => res(c ?? 1));
    p.on("error", () => res(1));
  });
}

// Both re-read gpg-agent.conf; reloadagent also drops every cached passphrase.
const reloadAgent = () => run("gpgconf", ["--reload", "gpg-agent"]);
const flushAgent = () => run("gpg-connect-agent", ["reloadagent", "/bye"]);

// Arranges for `relock <id>` to run when the window ends, so the TTL is restored even if nobody
// runs `lock`. A user systemd timer survives logout; a detached sleeper is the fallback.
// CRED_RELOCK=systemd|detached|off picks one (tests use detached).
function scheduleRelock(id: string, seconds: number): string {
  const how = process.env.CRED_RELOCK ?? "systemd";
  if (how === "off") return "off";
  const cmd = [process.execPath, import.meta.path, "relock", id];
  const env: Record<string, string> = {
    HOME: homedir(), PATH: process.env.PATH ?? "/usr/bin:/bin", GNUPGHOME: GNUPG_HOME,
    PASSWORD_STORE_DIR: PASS_STORE, CRED_STORE_DIR: PASS_STORE, CRED_MANIFEST: MANIFEST_PATH,
    CRED_STATE_DIR: STATE_DIR, CRED_AUDIT_DIR: AUDIT_DIR, CRED_SESSION_ID: SESSION,
  };
  if (how === "systemd") {
    const r = Bun.spawnSync([
      "systemd-run", "--user", "--quiet", `--unit=cred-relock-${id}`, `--on-active=${seconds}s`,
      "--timer-property=AccuracySec=1s", ...Object.entries(env).map(([k, v]) => `--setenv=${k}=${v}`), ...cmd,
    ], { stdout: "ignore", stderr: "ignore" });
    if (r.exitCode === 0) return "systemd";
  }
  const p = spawn("sh", ["-c", `sleep ${seconds}; exec "$0" "$@"`, ...cmd],
    { detached: true, stdio: "ignore", env: { ...process.env, ...env } });
  p.unref();
  return "detached";
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "0m";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

// ───────────────────────── read (internal only) ─────────────────────────

// The one place plaintext exists in this process. It is never returned to a
// caller, never printed, never logged — it goes straight into a child env.
function passShow(passPath: string): Promise<string> {
  return new Promise((res, rej) => {
    const p = spawn("pass", ["show", passPath], { stdio: ["ignore", "pipe", "pipe"], env: PASS_ENV });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => {
      if (code !== 0) return rej(new Error(`pass show failed: ${err.trim() || `exit ${code}`}`));
      res(out);
    });
    p.on("error", (e) => rej(new Error(`pass unavailable: ${e.message}`)));
  });
}

async function readValue(e: Entry): Promise<string> {
  const raw = await passShow(e.pass_path);
  const v = e.format === "full"
    ? raw.replace(/\r?\n$/, "")
    : raw.split("\n")[0].replace(/\r$/, "");   // first line, pass convention
  if (!v) throw new Error(`'${e.pass_path}' decrypted to an empty value`);
  return v;
}

// ───────────────────────── commands ─────────────────────────

// Names, mappings, usage. No values. This is what SessionStart injects.
function cmdList(): void {
  const m = loadManifest();
  const names = Object.keys(m);
  if (!names.length) {
    console.log(`No credentials in ${MANIFEST_PATH}. Add an entry there, then store its value with:\n` +
                `  ${SELF} set <name>`);
    return;
  }
  const w = Math.max(...names.map((n) => n.length));
  console.log("Available credentials — use via `cred exec`, never printed:\n");
  for (const n of names) {
    const e = m[n];
    const stored = existsSync(join(PASS_STORE, e.pass_path + ".gpg"));
    console.log(`  ${n.padEnd(w)}  ${e.describes}`);
    console.log(`  ${" ".repeat(w)}  -> injects $${e.env}` +
                `${e.risk ? ` | risk: ${e.risk}` : ""}` +
                `${stored ? "" : "  [NOT YET STORED]"}`);
    if (e.note) console.log(`  ${" ".repeat(w)}  note: ${e.note}`);
  }
  console.log(`\n  usage:  ${SELF} exec <name> -- <command...>`);
  console.log("  The value goes into the child's environment only, and the child's output");
  console.log("  is filtered: the value and its common encodings show as [cred:<name>].");
  console.log("  Whatever the child sends elsewhere (network, files) is not filtered.");
}

// The whole point. Decrypt -> inject -> run -> stream filtered output. Never return the value.
async function cmdExec(name: string, argv: string[]): Promise<number> {
  if (!argv.length) throw new Error(`nothing to run. Usage: exec ${name} -- <command...>`);
  const e = resolve(name);

  const bin = argv[0];
  if (DUMPERS.test(bin.split("/").pop() ?? "")) {
    audit({ event_type: "exec_blocked", key: name, command: bin, reason: "env-dumping command" });
    throw new Error(
      `refusing to run '${bin}' with an injected credential — it would print ` +
      `$${e.env} straight into the transcript, which is the exact leak this tool exists to prevent.`);
  }

  const value = await readValue(e);
  const marker = `[cred:${name}]`;
  const patterns = buildPatterns(value, e.format);
  const started = Date.now();
  audit({
    event_type: "exec", key: name, env: e.env, command: bin, risk: e.risk ?? "unset",
    argv: argv.map((a) => redactText(a, patterns, marker).slice(0, 1000)),
    cwd: process.cwd(), ppid: process.ppid,
  });
  if (!patterns.length) {
    console.error(`cred: '${name}' is shorter than ${MIN_REDACT} bytes, so its output is NOT filtered`);
  }

  const child = spawn(bin, argv.slice(1), {
    stdio: ["inherit", "pipe", "pipe"],
    env: { ...process.env, [e.env]: value },   // the only place it goes
  });
  const rOut = new StreamRedactor(patterns, marker);
  const rErr = new StreamRedactor(patterns, marker);
  const streams: [NodeJS.ReadableStream, Transform, NodeJS.WriteStream][] = [
    [child.stdout!, redactStream(rOut), process.stdout],
    [child.stderr!, redactStream(rErr), process.stderr],
  ];
  const drained = streams.map(([src, t, dst]) => {
    // A reader that goes away (`| head`) gets the shell's treatment: the child is sent SIGPIPE
    // and the rest of its output is dropped.
    const onError = (err: NodeJS.ErrnoException) => {
      if (err.code !== "EPIPE") return;
      t.unpipe(dst);
      t.resume();
      child.kill("SIGPIPE");
    };
    dst.on("error", onError);
    src.pipe(t).pipe(dst, { end: false });
    return new Promise<void>((res) => t.on("end", () => { dst.off("error", onError); res(); }));
  });

  // A Ctrl-C at a terminal already reaches the child (same process group); anything else is passed on.
  const forward = (sig: NodeJS.Signals) => () => {
    if (sig === "SIGINT" && process.stdin.isTTY) return;
    child.kill(sig);
  };
  const handlers = (["SIGINT", "SIGTERM", "SIGHUP"] as NodeJS.Signals[]).map((s) => [s, forward(s)] as const);
  for (const [s, h] of handlers) process.on(s, h);

  const [code, signal] = await new Promise<[number | null, NodeJS.Signals | null]>((res) => {
    child.on("close", (c, s) => res([c, s]));
    child.on("error", (err) => {
      console.error(`cred: cannot run '${bin}': ${err.message}`);
      res([127, null]);
    });
  });
  if (code === 127 && signal === null && child.pid === undefined) for (const [, t] of streams) t.end();
  await Promise.all(drained);
  for (const [s, h] of handlers) process.off(s, h);

  const exit = code ?? 128 + (signal ? osConstants.signals[signal] ?? 0 : 0);
  const redactions = rOut.count + rErr.count;
  if (redactions) console.error(`cred: filtered ${redactions} occurrence(s) of $${e.env} from the output (shown as ${marker})`);
  audit({ event_type: "exec_done", key: name, exit, signal, duration_ms: Date.now() - started, redactions });
  return exit;
}

// The user types the value on their tty. Never argv — argv would be in the transcript.
async function cmdSet(name: string): Promise<number> {
  const m = loadManifest();
  const e = m[name];
  if (!e) throw new Error(`'${name}' is not in the manifest (${MANIFEST_PATH}). Add it first.`);
  if (!process.stdin.isTTY) {
    throw new Error(
      "refusing to read a secret from a pipe — this must be typed interactively.\n" +
      "  Run it yourself in a terminal:\n" +
      `    ${SELF} set ${name}\n` +
      "  (in Claude Code, prefix it with ! so it runs on your tty)");
  }
  return withEchoOff(() => {
    console.error(`Storing '${name}' -> ${e.pass_path}`);
    console.error("Type the value at the prompt. It is not echoed and never reaches the session.\n");
    const args = e.format === "full" ? ["insert", "--multiline", "--force", e.pass_path] : ["insert", "--force", e.pass_path];
    const p = spawn("pass", args, { stdio: "inherit", env: PASS_ENV });
    return new Promise<number>((res) => {
      p.on("error", (err) => {
        console.error(`cred: cannot run 'pass': ${err.message}`);
        res(127);
      });
      p.on("close", (c, s) => {
        if (c === 0) { audit({ event_type: "set", key: name }); console.error(`\nStored. ${name} is now usable via 'cred exec ${name} -- <cmd>'.`); }
        res(c ?? 128 + (s ? osConstants.signals[s] ?? 0 : 0));
      });
    });
  });
}

// Terminal echo stays off from before the first message until the prompting child is done. A
// value typed or pasted ahead of pass's or pinentry's prompt would otherwise be echoed, and a
// session that captures the command's output (Claude Code's `!`) would record it. Ctrl-C still
// reaches the child; this process stays alive long enough to put the terminal back. After Ctrl-Z
// and `fg` the shell has put its own modes back, so echo is turned off again on SIGCONT.
async function withEchoOff<T>(fn: () => Promise<T>): Promise<T> {
  const saved = spawnSync("stty", ["-g"], { stdio: ["inherit", "pipe", "ignore"], encoding: "utf8" });
  const restore = saved.status === 0 ? saved.stdout.trim() : "";
  const echoOff = () => { if (restore) spawnSync("stty", ["-echo"], { stdio: ["inherit", "ignore", "ignore"] }); };
  const ignore = () => {};
  echoOff();
  process.on("SIGINT", ignore);
  process.on("SIGCONT", echoOff);
  try {
    return await fn();
  } finally {
    process.off("SIGINT", ignore);
    process.off("SIGCONT", echoOff);
    if (restore) spawnSync("stty", [restore], { stdio: ["inherit", "ignore", "ignore"] });
  }
}

// Seed gpg-agent's passphrase cache for up to MAX_UNLOCK_HOURS. Rewrites
// gpg-agent.conf so the TTL matches the requested window exactly — gpg-agent's
// own timer IS the timer. When the window ends (or on `lock`) the user's own
// TTL lines are put back, so later passphrase prompts are not cached for hours.
async function cmdUnlock(hoursArg: string | undefined): Promise<number> {
  let hours = MAX_UNLOCK_HOURS;
  if (hoursArg !== undefined) {
    const parsed = Number(hoursArg);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`invalid hours '${hoursArg}' — must be a positive number`);
    }
    if (parsed > MAX_UNLOCK_HOURS) {
      throw new Error(`refusing to unlock for ${parsed}h — cap is ${MAX_UNLOCK_HOURS}h`);
    }
    hours = parsed;
  }
  if (!process.stdin.isTTY) {
    throw new Error(
      "refusing to unlock from a pipe — the passphrase must be entered on your tty.\n" +
      "  In Claude Code, prefix it with ! so it runs on your tty:\n" +
      `    ! ${SELF} unlock ${hours}`);
  }

  const m = loadManifest();
  const priming = Object.entries(m).find(([, e]) =>
    existsSync(join(PASS_STORE, e.pass_path + ".gpg")));
  if (!priming) {
    throw new Error(
      "no stored credentials to prime the cache with. Add one first:\n" +
      `  ${SELF} set <name>`);
  }

  // The TTL lines in the file are the user's own unless we marked them; ours are never saved as theirs.
  const conf = readAgentConf();
  const ttlRestore = conf.managed ? (readUnlockState()?.ttl_restore ?? NO_TTL) : conf.ttl;

  const seconds = Math.max(1, Math.round(hours * 3600));
  setAgentTtl({ "default-cache-ttl": String(seconds), "max-cache-ttl": String(seconds) }, true);
  const reloadCode = await reloadAgent();
  if (reloadCode !== 0) {
    console.error("cred: warning — gpgconf --reload gpg-agent returned non-zero. TTL may not have taken effect.");
  }

  try {
    await withEchoOff(async () => {
      console.error(`Unlocking cred for ${hours}h. GPG will prompt for your passphrase now.`);
      console.error("The passphrase talks to gpg-agent directly — it never enters this process.\n");
      await passShow(priming[1].pass_path);
    });
  } catch (err) {
    setAgentTtl(ttlRestore, false);
    await reloadAgent();
    throw new Error(`unlock failed: ${(err as Error).message}`);
  }

  const now = new Date();
  const expires = new Date(now.getTime() + seconds * 1000);
  const state: UnlockState = {
    unlocked_at: now.toISOString(),
    expires_at: expires.toISOString(),
    hours,
    by_session: SESSION,
    window_id: randomBytes(6).toString("hex"),
    ttl_restore: ttlRestore,
  };
  writeUnlockState(state);
  const relock = scheduleRelock(state.window_id, seconds);
  audit({ event_type: "unlock", hours, expires_at: state.expires_at, window_id: state.window_id, relock });

  console.error(`Unlocked until ${expires.toISOString()} (${hours}h).`);
  if (relock === "off") console.error("No expiry relock scheduled (CRED_RELOCK=off): run `lock` when done.");
  console.error(`Lock early with:  ${SELF} lock`);
  return 0;
}

// Flush gpg-agent's cache, put the user's TTL lines back, and clear the state.
async function lockNow(event: "lock" | "relock"): Promise<number> {
  const conf = readAgentConf();
  if (conf.managed) setAgentTtl(readUnlockState()?.ttl_restore ?? NO_TTL, false);
  const code = await flushAgent();
  clearUnlockState();
  audit({ event_type: event, agent_reload_exit: code, ttl_restored: conf.managed });
  if (code === 0) {
    console.error("Locked. gpg-agent cache flushed.");
  } else {
    console.error("gpg-connect-agent reloadagent returned non-zero — cache state uncertain.");
  }
  return code;
}

// Run by the expiry timer. A later `unlock` starts a new window, which this must not cut short.
async function cmdRelock(id: string | undefined): Promise<number> {
  const s = readUnlockState();
  if (!id || s?.window_id !== id) {
    audit({ event_type: "relock_skipped", window_id: id ?? null, current: s?.window_id ?? null });
    return 0;
  }
  return lockNow("relock");
}

// Advisory view of the unlock window. Honest about staleness — if gpg-agent
// was restarted the cache may be gone even though the state file still says
// "unlocked"; the next `exec` will re-prompt.
function cmdUnlockStatus(): void {
  const s = readUnlockState();
  if (!s) {
    console.log("locked");
    return;
  }
  const now = Date.now();
  const expires = new Date(s.expires_at).getTime();
  if (!Number.isFinite(expires) || now >= expires) {
    console.log(`stale — recorded expiry ${s.expires_at} has passed; next 'cred exec' will re-prompt`);
    return;
  }
  console.log(
    `unlocked until ${s.expires_at} (${formatRemaining(expires - now)} left, ${s.hours}h window from ${s.unlocked_at})`);
}

function cmdStatus(name: string): void {
  const e = resolve(name);
  console.log(JSON.stringify({
    name, describes: e.describes, env: e.env, risk: e.risk ?? "unset",
    format: e.format ?? "line", stored: true, value: "<never disclosed>",
  }, null, 2));
}

// ───────────────────────── doctor ─────────────────────────

function version(): string {
  try {
    return (JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")) as { version: string }).version;
  } catch { return "dev"; }
}

// Lets an installed copy be compared with the repo it came from.
function sourceHash(): string {
  const h = createHash("sha256");
  for (const f of ["cred.ts", "guard.ts", "session-start.ts"]) {
    const p = join(import.meta.dir, f);
    if (existsSync(p)) h.update(readFileSync(p));
  }
  return h.digest("hex").slice(0, 12);
}

interface HookEntry { matcher?: string; hooks?: { command?: string }[] }

// Claude Code hook registrations from the user and project settings files.
function claudeHooks(): { pre: HookEntry[]; start: HookEntry[]; files: string[] } {
  const dir = process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude");
  const files = [join(dir, "settings.json"), join(dir, "settings.local.json"),
                 join(process.cwd(), ".claude", "settings.json"), join(process.cwd(), ".claude", "settings.local.json")]
    .filter((p) => existsSync(p));
  const pre: HookEntry[] = [], start: HookEntry[] = [];
  for (const p of files) {
    try {
      const j = JSON.parse(readFileSync(p, "utf8")) as { hooks?: { PreToolUse?: HookEntry[]; SessionStart?: HookEntry[] } };
      pre.push(...(j.hooks?.PreToolUse ?? []));
      start.push(...(j.hooks?.SessionStart ?? []));
    } catch { /* reported as not found */ }
  }
  return { pre, start, files };
}

const commandsOf = (es: HookEntry[]) => es.flatMap((e) => (e.hooks ?? []).map((h) => ({ matcher: e.matcher ?? "", command: h.command ?? "" })));

async function cmdDoctor(): Promise<number> {
  let failed = 0;
  const ok = (what: string, detail = "") => console.log(`  ok    ${what}${detail ? `  (${detail})` : ""}`);
  const warn = (what: string, fix = "") => console.log(`  warn  ${what}${fix ? "\n        " + fix.replace(/\n/g, "\n        ") : ""}`);
  const fail = (what: string, fix: string) => { failed++; console.log(`  FAIL  ${what}\n        ${fix.replace(/\n/g, "\n        ")}`); };

  console.log(`cred-broker ${version()} (source ${sourceHash()})\n`);
  if (process.platform === "linux") ok("platform", "linux");
  else warn(`platform ${process.platform} is untested`, "Linux is the tested platform; please report what breaks.");

  const gpg = Bun.which("gpg");
  if (gpg) ok("gpg", gpg); else fail("gpg not found", "install GnuPG, e.g.  sudo apt install gnupg");
  const pass = Bun.which("pass");
  if (pass) ok("pass", pass); else fail("pass not found", "install pass, e.g.  sudo apt install pass");

  if (existsSync(join(PASS_STORE, ".gpg-id"))) ok("password store", PASS_STORE);
  else fail(`no password store at ${PASS_STORE}`,
    "create a key (skip if you have one), then initialise the store:\n" +
    '  gpg --quick-generate-key "Your Name <you@example.com>" default default never\n' +
    `  PASSWORD_STORE_DIR=${PASS_STORE} pass init you@example.com`);

  let manifest: Manifest | null = null;
  if (!existsSync(MANIFEST_PATH)) {
    fail(`no manifest at ${MANIFEST_PATH}`, "copy examples/manifest.example.yaml there and edit it");
  } else {
    try { manifest = loadManifest(); ok("manifest", `${MANIFEST_PATH}, ${Object.keys(manifest).length} entr${Object.keys(manifest).length === 1 ? "y" : "ies"}`); }
    catch (err) { fail(`manifest does not parse: ${MANIFEST_PATH}`, (err as Error).message); }
  }
  for (const [n, e] of Object.entries(manifest ?? {})) {
    if (!existsSync(join(PASS_STORE, e.pass_path + ".gpg"))) warn(`'${n}' is not stored yet`, `run in your own terminal:  ${SELF} set ${n}`);
  }

  const agent = Bun.spawnSync(["gpg-connect-agent", "/bye"], { stdout: "ignore", stderr: "ignore", env: { ...process.env, GNUPGHOME: GNUPG_HOME } });
  if (agent.exitCode === 0) ok("gpg-agent reachable"); else warn("gpg-agent not reachable", "it starts on first use; check GNUPGHOME if this persists");
  if (Bun.which("systemd-run")) ok("expiry relock", "systemd user timer");
  else warn("systemd-run not found", "unlock windows will close via a detached sleep process instead");

  const hooks = claudeHooks();
  if (!hooks.files.length) {
    warn("no Claude Code settings found", "see README, \"Claude Code setup\" (skip this if you use another agent)");
  } else {
    // This project's guard (src/guard.ts) or a wrapper named for it (e.g. cred-guard), not any hook
    // with "guard" in its name. The same hook can be listed in more than one settings file.
    const isOurs = (c: string) => /(^|[\/"'\s])guard\.ts\b|cred[-_]?guard|cred-broker\/.*guard/i.test(c);
    const guard = commandsOf(hooks.pre).filter((h) => isOurs(h.command))
      .filter((h, i, all) => all.findIndex((o) => o.command === h.command && o.matcher === h.matcher) === i);
    if (!guard.length) warn("guard hook not registered", "add src/guard.ts as a PreToolUse hook for Bash|Read|Grep|Glob (README)");
    else {
      const covers = (tool: string) => guard.some((h) => h.matcher === "" || h.matcher === "*" || h.matcher.split("|").includes(tool));
      const missing = ["Bash", "Read", "Grep", "Glob"].filter((t) => !covers(t));
      if (missing.length) warn(`guard hook does not cover ${missing.join(", ")}`, "extend its matcher to Bash|Read|Grep|Glob");
      else ok("guard hook registered", "PreToolUse Bash|Read|Grep|Glob");
      // A hook that crashes or cannot start is treated by Claude Code as "allow", so run it.
      const probe = JSON.stringify({ tool_name: "Bash", tool_input: { command: "pass show cred-doctor-probe" }, cwd: "/" });
      for (const h of guard.filter((g, i) => guard.findIndex((o) => o.command === g.command) === i)) {
        const r = Bun.spawnSync(["sh", "-c", h.command], { stdin: Buffer.from(probe), stdout: "pipe", stderr: "pipe", timeout: 15_000 });
        if (/"permissionDecision"\s*:\s*"deny"/.test(r.stdout.toString())) ok("guard hook works", "it denied a `pass show` probe");
        else fail(`guard hook did not deny a probe: ${h.command}`, `run it by hand:  echo '${probe}' | ${h.command}`);
      }
    }
    const ss = commandsOf(hooks.start).filter((h) => /session-start|cred.*manifest/i.test(h.command));
    if (ss.length) ok("session-start hook"); else warn("session-start hook not registered", "add src/session-start.ts as a SessionStart hook (README)");
  }

  for (const k of ["CRED_MANIFEST", "CRED_STATE_DIR", "CRED_AUDIT_DIR", "CRED_STORE_DIR"]) {
    if (process.env[k]) console.log(`  info  ${k}=${process.env[k]}`);
  }
  console.log(`  info  audit log: ${AUDIT_DIR}`);
  console.log(failed ? `\n${failed} check(s) failed.` : "\nAll required checks passed.");
  return failed ? 1 : 0;
}

// ───────────────────────── entry ─────────────────────────

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = argv;
  const cmd = args[0];
  try {
    switch (cmd) {
      case "list": cmdList(); return 0;
      case "status": {
        if (!args[1]) throw new Error("Usage: status <name>");
        cmdStatus(args[1]); return 0;
      }
      case "set": {
        if (!args[1]) throw new Error("Usage: set <name>");
        return await cmdSet(args[1]);
      }
      case "exec": {
        // The `--` is required: it is what tells a reader (and the guard hook) where the command
        // starts, so `exec github pass show other` cannot slip a second secret past both.
        if (!args[1] || args[2] !== "--" || args.length < 4) throw new Error("Usage: exec <name> -- <command...>");
        return await cmdExec(args[1], args.slice(3));
      }
      case "unlock": return await cmdUnlock(args[1]);
      case "lock": return await lockNow("lock");
      case "relock": return await cmdRelock(args[1]);
      case "unlock-status": cmdUnlockStatus(); return 0;
      case "doctor": return await cmdDoctor();
      case "version": case "--version": console.log(`cred-broker ${version()} (source ${sourceHash()})`); return 0;
      default:
        console.error(
          "cred — a local credential broker for AI agents. Secrets are never printed, by design.\n\n" +
          "  list                     what exists and what it maps to (no values)\n" +
          "  exec <name> -- <cmd>     run <cmd> with the secret in its env; its output is filtered\n" +
          "  status <name>            metadata for one entry (no value)\n" +
          "  set <name>               store a value: interactive, on your own tty only\n" +
          `  unlock [hours]           hold gpg-agent's passphrase cache for up to ${MAX_UNLOCK_HOURS}h (default ${MAX_UNLOCK_HOURS})\n` +
          "  lock                     flush gpg-agent's cache and restore its TTL settings\n" +
          "  unlock-status            show the remaining unlock window (advisory)\n" +
          "  doctor                   check the setup: gpg, pass, store, manifest, agent hooks\n" +
          "  version                  print the version and a hash of the source\n" +
          "  relock <id>              (run by the expiry timer) lock if window <id> is still open\n\n" +
          "There is deliberately no `get` or `show`: anything printed reaches the agent's\n" +
          "transcript and the model provider, which is the leak this tool prevents.");
        return cmd && cmd !== "help" && cmd !== "--help" && cmd !== "-h" ? 1 : 0;
    }
  } catch (err) {
    console.error(`cred: ${(err as Error).message}`);
    return 1;
  }
}

// exitCode, not exit(): exit() can cut off filtered output still being written to a pipe.
if (import.meta.main) process.exitCode = await main();
