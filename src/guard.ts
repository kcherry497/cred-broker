#!/usr/bin/env bun
// guard — Claude Code PreToolUse hook (Bash, Read, Grep, Glob).
//
// Denies tool calls that would read the password store directly: `pass show`, `pass <name>`,
// `gpg -d`, `bash -c '…'` wrapping either, a path into the store or into gpg's private keys.
// The agent is told to use the broker instead, which injects the value into a child process
// and keeps it out of the transcript.
//
// This is a tripwire for an honest agent, not a security boundary. Anything running as your
// user can reach gpg-agent's socket directly, and code can build "pass" at runtime. The real
// boundaries are gpg-agent (cache TTL, pinentry) and running decryption as another user. See
// the README's threat model.
//
// Policy: allowlists, not blocklists. Only `pass` subcommands that list names, and only gpg
// command options that cannot decrypt, are allowed. Anything unknown is denied.
// Errors: garbage hook input fails open (never brick a session); a command that mentions a
// trigger word and cannot be parsed fails closed.

import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

export interface Verdict { rule: string; what: string }

export interface GuardConfig {
  home: string;       // for ~ and $HOME in paths
  gnupg: string;      // GNUPGHOME: archiving or copying it hands over key material
  extraVars: string[]; // more variables that would reconfigure the broker (CRED_GUARD_EXTRA_VARS)
  stores: string[];   // password-store directories (absolute)
  brokerCmd: string;  // how the agent should run the broker, shown in the deny message
}

export function defaultConfig(env: Record<string, string | undefined> = process.env): GuardConfig {
  const home = env.HOME ?? homedir();
  const stores = [env.CRED_STORE_DIR, env.PASSWORD_STORE_DIR, join(home, ".password-store")]
    .filter((s): s is string => !!s).map((s) => resolve(s.replace(/^~(?=\/|$)/, home)));
  return {
    home,
    gnupg: resolve((env.GNUPGHOME || join(home, ".gnupg")).replace(/^~(?=\/|$)/, home)),
    extraVars: (env.CRED_GUARD_EXTRA_VARS ?? "").split(",").map((v) => v.trim()).filter(Boolean),
    stores: [...new Set(stores)],
    brokerCmd: env.CRED_CMD ?? `bun ${join(import.meta.dir, "cred.ts")}`,
  };
}

// ───────────────────────── tool dispatch ─────────────────────────

export function inspectTool(
  tool: string, input: Record<string, unknown>, cwd: string | undefined, cfg: GuardConfig,
): Verdict | null {
  if (typeof cwd !== "string") cwd = undefined;
  if (cwd && insideStore(cwd, cfg)) {
    return { rule: "store-cwd", what: "the working directory is inside the password store" };
  }
  if (tool === "Bash") return inspectCommand(String(input.command ?? ""), cfg, cwd);
  if (tool === "Read" || tool === "Grep" || tool === "Glob") {
    // Grep's `pattern` is a regex, not a path; Glob's is a path pattern.
    const keys = tool === "Grep" ? ["path", "glob"] : tool === "Glob" ? ["pattern", "path"] : ["file_path"];
    for (const k of keys) {
      const v = input[k];
      const base = tool === "Glob" && typeof input.path === "string" ? input.path : cwd;
      if (typeof v === "string" && (sensitivePath(v, cfg) || sensitivePath(absolute(v, base, cfg), cfg))) {
        return { rule: "store-path", what: `${tool} on a password-store or private-key path` };
      }
    }
  }
  return null;
}

function insideStore(p: string, cfg: GuardConfig): boolean {
  const abs = resolve(p);
  return cfg.stores.some((s) => abs === s || abs.startsWith(s + "/"));
}

// A word that names the store or gpg's secret keys. Only path-like words (no whitespace) count,
// so prose in a commit message does not trip it.
function sensitivePath(word: string, cfg: GuardConfig): boolean {
  if (/\s/.test(word)) return false;
  if (/\.password-store|\$\{?PASSWORD_STORE_DIR|private-keys-v1\.d|secring\.gpg/.test(word)) return true;
  if (/\/\.p[^/]*[*?[]/.test(word)) return true;  // ~/.pass* style globs
  const expanded = word.replace(/^~(?=\/|$)/, cfg.home).replace(/^\$\{?HOME\}?(?=\/|$)/, cfg.home);
  return cfg.stores.some((s) => expanded === s || expanded.startsWith(s + "/") || containsPath(word, s) || globReaches(expanded, s));
}

// A relative word made absolute against a known directory; other words unchanged.
function absolute(word: string, base: string | undefined, cfg: GuardConfig): string {
  if (!base || /^[\/~$-]/.test(word) || /\s/.test(word) || word === "") return word;
  return resolve(base.replace(/^~(?=\/|$)/, cfg.home), word);
}

// Could this glob match the store or something under it? Compared segment by segment.
function globReaches(glob: string, store: string): boolean {
  if (!/[*?[]/.test(glob) || !glob.startsWith("/")) return false;
  const g = glob.split("/").filter(Boolean), st = store.split("/").filter(Boolean);
  for (let i = 0; i < st.length; i++) {
    if (i >= g.length) return false;
    if (g[i] === "**") return true;
    let re: RegExp;
    try {
      re = new RegExp("^" + g[i].replace(/[.+^${}()|\\]/g, (c) => "\\" + c).replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
    } catch {
      re = new RegExp("^" + g[i].replace(/[.+^${}()|[\]\\]/g, (c) => "\\" + c).replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
    }
    if (!re.test(st[i])) return false;
  }
  return true;
}

// `--dir=/srv/vault/x` or `a:/srv/vault`, but not `/srv/vault-backup`.
function containsPath(word: string, dir: string): boolean {
  for (let i = word.indexOf(dir); i >= 0; i = word.indexOf(dir, i + 1)) {
    const before = i === 0 ? "" : word[i - 1];
    const after = word[i + dir.length] ?? "";
    if ((before === "" || "=:\"'".includes(before)) && (after === "" || after === "/")) return true;
  }
  return false;
}

// ───────────────────────── commands ─────────────────────────

// Cheap prefilter: commands without any of these are not parsed at all.
const TRIGGER = /pass|gpg|gnupg|password-store|PASSWORD_STORE|private-keys|secring|CRED_|\$'|\\x[0-9a-fA-F]|\\[0-7]{3}/;
// A real mention, not "password" or "--passphrase-file": used where a guess must be made.
const STRONG = /\bpass\b|\bgpg|password-store|PASSWORD_STORE|private-keys|secring/;

const MAX_COMMAND = 1_000_000;

export function inspectCommand(cmd: string, cfg: GuardConfig, cwd?: string): Verdict | null {
  const bare = cmd.replace(/\\\n|["'\\]/g, "");
  const mentions = (s: string) => cmd.includes(s) || bare.includes(s);
  if (!TRIGGER.test(cmd) && !TRIGGER.test(bare) && ![...cfg.stores, cfg.gnupg, ...cfg.extraVars].some(mentions)) return null;
  if (cmd.length > MAX_COMMAND) return { rule: "unparsed", what: "the command is too long to check" };
  try {
    return new Parser(cmd, cfg, 0, new Map(), cwd).script();
  } catch (err) {
    if (err instanceof Denied) return err.verdict;
    return { rule: "unparsed", what: `the command mentions pass/gpg and could not be checked (${(err as Error).message})` };
  }
}

interface Word { text: string; dynamic: boolean }
interface Heredoc { delim: string; strip: boolean; quoted: boolean; body?: string }
interface Simple { words: Word[]; redirs: string[]; heredocs: Heredoc[]; herestrings: string[]; from?: Simple }

const MAX_DEPTH = 16;

class Parser {
  private i = 0;
  private pendingDocs: Heredoc[] = [];

  constructor(private s: string, private cfg: GuardConfig, private depth: number,
              private vars = new Map<string, string>(), private cwd?: string) {
    if (depth > MAX_DEPTH) throw new Error("nested too deep");
  }

  // Parse to end of input; return the first denial.
  script(): Verdict | null {
    const v = this.list(null);
    if (v) return v;
    if (this.i < this.s.length) throw new Error(`unexpected '${this.s[this.i]}' at ${this.i}`);
    return null;
  }

  private sub(text: string): Verdict | null {
    return new Parser(text, this.cfg, this.depth + 1, this.vars, this.cwd).script();
  }

  // Text the shell expands but does not run as commands (an unquoted heredoc body, the default
  // in ${x:-…}, the inside of $((…))): only its command substitutions are checked.
  private expandOnly(text: string): void {
    const p = new Parser(text, this.cfg, this.depth + 1, this.vars, this.cwd);
    while (p.i < p.s.length) {
      const ch = p.s[p.i];
      if (ch === "\\") { p.i += 2; continue; }
      if (ch === "`") { p.i++; p.backtick(); continue; }
      if (ch === "$") { p.dollar(true); continue; }
      p.i++;
    }
  }

  // A sequence of simple commands joined by operators, up to `close` (")" for $(…) and (…)).
  private list(close: string | null): Verdict | null {
    let cur: Simple = blank();
    // `from` links a command to the one piping into it, so what that one writes (heredoc bodies,
    // echo/printf arguments) is checked too: `cat <<EOF | bash`, `echo 'pass show x' | sh`.
    const flush = (pipe = false): Verdict | null => {
      const c = cur; cur = blank();
      if (pipe) cur.from = c;   // heredoc bodies are read later, at the newline, so keep the reference
      return c.words.length || c.redirs.length ? this.check(c) : null;
    };
    while (this.i < this.s.length) {
      const ch = this.s[this.i];
      if (close && ch === close) {
        const v = flush(); this.i++; return v;
      }
      if (ch === "\n") {
        this.i++;
        this.readHeredocs();
        const v = flush(); if (v) return v;
        continue;
      }
      if (ch === " " || ch === "\t" || ch === "\r") { this.i++; continue; }
      if (ch === "#") { while (this.i < this.s.length && this.s[this.i] !== "\n") this.i++; continue; }
      if (ch === "&" && this.s[this.i + 1] === ">") { this.redirect(cur, "&"); continue; }   // &> file
      if (ch === ";" || ch === "&" || ch === "|") {
        this.i++;
        const two = this.s[this.i];
        const pipe = ch === "|" && two !== "|";
        if (two === ch || (ch === "|" && two === "&") || (ch === ";" && two === "&")) this.i++;
        const v = flush(pipe); if (v) return v;
        continue;
      }
      if (ch === "(") {
        this.i++;
        const v = flush() ?? this.list(")"); if (v) return v;
        continue;
      }
      if (ch === ")") {                 // a `case` pattern such as `a)`; ends that word list
        this.i++;
        const v = flush(); if (v) return v;
        continue;
      }
      if (ch === "<" || ch === ">") {
        if (this.s[this.i + 1] === "(") {           // process substitution
          this.i += 2; const v = this.list(")"); if (v) return v; continue;
        }
        this.redirect(cur, ch); continue;
      }
      const w = this.word(cur);
      if (w === null) continue;
      // fd number before a redirect: 2>file
      if (/^\d+$/.test(w.text) && !w.dynamic && (this.s[this.i] === "<" || this.s[this.i] === ">")) continue;
      cur.words.push(w);
    }
    if (close) throw new Error(`missing ${close}`);
    this.readHeredocs();
    return flush();
  }

  private redirect(cur: Simple, ch: string): void {
    let op = ch; this.i++;
    while (this.s[this.i] === "<" || this.s[this.i] === ">" || this.s[this.i] === "&" || this.s[this.i] === "-" || this.s[this.i] === "|") {
      op += this.s[this.i++];
    }
    this.skipBlanks();
    if (op === "<<" || op === "<<-") {
      const start = this.i;
      const w = this.word(cur);
      if (!w) throw new Error("heredoc without delimiter");
      const doc: Heredoc = { delim: w.text, strip: op === "<<-", quoted: /['"\\]/.test(this.s.slice(start, this.i)) };
      cur.heredocs.push(doc); this.pendingDocs.push(doc);
      return;
    }
    const w = this.word(cur);
    if (!w) return;
    if (op === "<<<") cur.herestrings.push(w.text); else cur.redirs.push(w.text);
  }

  private readHeredocs(): void {
    while (this.pendingDocs.length) {
      const doc = this.pendingDocs.shift()!;
      const lines: string[] = [];
      for (;;) {
        if (this.i >= this.s.length) break;          // unterminated: bash takes the rest
        let end = this.s.indexOf("\n", this.i);
        if (end < 0) end = this.s.length;
        let line = this.s.slice(this.i, end);
        this.i = Math.min(end + 1, this.s.length);
        if (doc.strip) line = line.replace(/^\t+/, "");
        if (line === doc.delim) break;
        lines.push(line);
      }
      doc.body = lines.join("\n");
      if (!doc.quoted) this.expandOnly(doc.body);   // unquoted: $(…) and `…` in the body run
    }
  }

  private skipBlanks(): void {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++;
  }

  // One shell word with quotes removed. Command substitutions inside it are checked as they
  // are found; their output is unknown, so the word is marked dynamic.
  private word(cur: Simple): Word | null {
    let text = "", dynamic = false, any = false;
    const s = this.s;
    while (this.i < s.length) {
      const ch = s[this.i];
      if (" \t\n;&|()<>".includes(ch)) break;
      any = true;
      if (ch === "\\") {
        if (s[this.i + 1] === "\n") { this.i += 2; continue; }
        text += s[this.i + 1] ?? ""; this.i += 2; continue;
      }
      if (ch === "'") {
        const end = s.indexOf("'", this.i + 1);
        if (end < 0) throw new Error("unclosed '");
        text += s.slice(this.i + 1, end); this.i = end + 1; continue;
      }
      if (ch === '"') { this.i++; const r = this.dquote(); text += r.text; dynamic ||= r.dynamic; continue; }
      if (ch === "`") { this.i++; this.backtick(); text += "\u0000"; dynamic = true; continue; }
      if (ch === "$") {
        const r = this.dollar();
        text += r.text; dynamic ||= r.dynamic; continue;
      }
      text += ch; this.i++;
    }
    return any ? { text, dynamic } : null;
  }

  private dquote(): { text: string; dynamic: boolean } {
    let text = "", dynamic = false;
    const s = this.s;
    while (this.i < s.length && s[this.i] !== '"') {
      const ch = s[this.i];
      if (ch === "\\" && '"\\$`\n'.includes(s[this.i + 1] ?? "")) {
        if (s[this.i + 1] !== "\n") text += s[this.i + 1];
        this.i += 2; continue;
      }
      if (ch === "`") { this.i++; this.backtick(); text += "\u0000"; dynamic = true; continue; }
      if (ch === "$") { const r = this.dollar(true); text += r.text; dynamic ||= r.dynamic; continue; }
      text += ch; this.i++;
    }
    if (s[this.i] !== '"') throw new Error('unclosed "');
    this.i++;
    return { text, dynamic };
  }

  // $(…), $((…)), ${…}, $name, $'…' (decoded, so $'\x70ass' reads as pass).
  private dollar(inQuotes = false): { text: string; dynamic: boolean } {
    const s = this.s;
    const next = s[this.i + 1];
    if (next === "(" && s[this.i + 2] === "(") {
      const end = s.lastIndexOf("))", s.indexOf("))", this.i + 3) >= 0 ? s.length : -1);
      const close = s.indexOf("))", this.i + 3);
      if (close < 0 || end < 0) throw new Error("unclosed $((");
      // The matching "))" is the first one at which parentheses balance.
      let depth = 0, j = this.i + 3;
      for (; j < s.length; j++) {
        if (s[j] === "(") depth++;
        else if (s[j] === ")") { if (depth === 0 && s[j + 1] === ")") break; depth--; }
      }
      if (j >= s.length) throw new Error("unclosed $((");
      this.expandOnly(s.slice(this.i + 3, j));
      this.i = j + 2; return { text: "0", dynamic: true };
    }
    if (next === "(") {
      this.i += 2;
      const v = this.list(")");
      if (v) throw new Denied(v);
      return { text: "\u0000", dynamic: true };
    }
    if (next === "{") {
      let depth = 0, j = this.i + 1;
      for (; j < s.length; j++) {
        if (s[j] === "{") depth++;
        else if (s[j] === "}" && --depth === 0) break;
      }
      if (j >= s.length) throw new Error("unclosed ${");
      const inner = s.slice(this.i + 2, j);
      this.expandOnly(inner);                        // ${x:-$(…)} runs the default
      this.i = j + 1; return { text: "${" + inner + "}", dynamic: true };
    }
    if (next === "'" && !inQuotes) {
      const start = this.i + 2;
      let j = start, out = "";
      for (; j < s.length && s[j] !== "'"; j++) {
        if (s[j] === "\\" && j + 1 < s.length) {
          const e = s[++j];
          const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", "\\": "\\", "'": "'", '"': '"', a: "\x07", b: "\b", e: "\x1b", f: "\f", v: "\v" };
          if (e in simple) { out += simple[e]; continue; }
          if (e === "x") { const m = /^[0-9a-fA-F]{1,2}/.exec(s.slice(j + 1)); if (m) { out += String.fromCharCode(parseInt(m[0], 16)); j += m[0].length; continue; } }
          if (/[0-7]/.test(e)) { const m = /^[0-7]{1,3}/.exec(s.slice(j)); out += String.fromCharCode(parseInt(m![0], 8)); j += m![0].length - 1; continue; }
          if (e === "u" || e === "U") { const m = /^[0-9a-fA-F]{1,8}/.exec(s.slice(j + 1)); if (m) { out += String.fromCodePoint(parseInt(m[0], 16)); j += m[0].length; continue; } }
          out += "\\" + e; continue;
        }
        out += s[j];
      }
      if (j >= s.length) throw new Error("unclosed $'");
      this.i = j + 1; return { text: out, dynamic: false };
    }
    const m = /^[A-Za-z_][A-Za-z0-9_]*|^[0-9@*#?$!-]/.exec(s.slice(this.i + 1));
    if (m) { this.i += 1 + m[0].length; return { text: "$" + m[0], dynamic: true }; }
    this.i++; return { text: "$", dynamic: false };
  }

  private backtick(): void {
    const s = this.s;
    let j = this.i, inner = "";
    for (; j < s.length && s[j] !== "`"; j++) {
      if (s[j] === "\\" && "`\\$".includes(s[j + 1] ?? "")) { inner += s[++j]; continue; }
      inner += s[j];
    }
    if (j >= s.length) throw new Error("unclosed `");
    this.i = j + 1;
    const v = this.sub(inner);
    if (v) throw new Denied(v);
  }

  // ─── one simple command ───

  private check(c: Simple): Verdict | null {
    for (const w of [...c.words.map((w) => w.text), ...c.redirs]) {
      if (sensitivePath(w, this.cfg) || sensitivePath(absolute(w, this.cwd, this.cfg), this.cfg)) return { rule: "store-path", what: "it touches the password store or gpg's private keys" };
    }
    return this.command(c.words, c);
  }

  private command(words: Word[], c: Simple | null): Verdict | null {
    let k = 0;
    // assignments and reserved words in front of the command
    for (; k < words.length; k++) {
      const t = words[k].text;
      const a = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(t);
      if (a) {
        if (reconfigures(a[1], this.cfg)) return reconf(a[1]);
        continue;
      }
      if (["!", "{", "}", "then", "do", "else", "elif", "if", "while", "until", "fi", "done", "esac", "coproc"].includes(t)) continue;
      break;
    }
    if (k >= words.length) {
      // A line of plain assignments: remember literal values so `$SSH host` can be resolved.
      for (const w of words) {
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(w.text);
        if (m && !w.dynamic) this.vars.set(m[1], m[2]); else if (m) this.vars.delete(m[1]);
      }
      return null;
    }
    const head = words[k];
    const args = words.slice(k + 1);
    const name = basename(head.text.replace(/^\\/, ""));
    if (head.dynamic) {
      const ref = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(head.text);
      const val = ref ? this.vars.get(ref[1]) : undefined;
      if (val !== undefined && c !== null) {
        const expanded = val.split(/\s+/).filter(Boolean).map((text) => ({ text, dynamic: false }));
        return this.command([...expanded, ...words.slice(k + 1)], c);
      }
      const own = [...words.slice(k).map((w) => w.text), ...bodies(c)].join(" ");
      if (STRONG.test(own)) return { rule: "dynamic", what: `the command name (${head.text.slice(0, 40)}) is computed at run time and the command mentions pass/gpg` };
      return null;
    }
    const sub = (from: number) => this.command(args.slice(from), null);
    const t = args.map((a) => a.text);

    switch (name) {
      case "cd": case "pushd": {
        const dir = t.find((a) => !a.startsWith("-"));
        if (dir && !args.find((a) => a.text === dir)?.dynamic) {
          this.cwd = resolve((this.cwd ?? "/").replace(/^~(?=\/|$)/, this.cfg.home), dir.replace(/^~(?=\/|$)/, this.cfg.home));
          if (insideStore(this.cwd, this.cfg)) return { rule: "store-cwd", what: "it changes into the password store" };
        } else this.cwd = undefined;
        return null;
      }
      case "time": return sub(skipOpts(t, ["-o", "-f", "--output", "--format"]));
      case "export": case "declare": case "typeset": case "local": case "readonly":
        for (const a of t) { const m = /^([A-Za-z_][A-Za-z0-9_]*)(=|$)/.exec(a); if (m && reconfigures(m[1], this.cfg) && m[2] === "=") return reconf(m[1]); }
        return null;
      case "sudo": case "doas": return sub(skipOpts(t, ["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T"]));
      case "env": {
        let j = 0;
        for (; j < t.length; j++) {
          if (t[j] === "-u" || t[j] === "-C" || t[j] === "--chdir" || t[j] === "--unset") { j++; continue; }
          if (t[j] === "-S" || t[j] === "--split-string") return this.sub(t.slice(j + 1).join(" "));
          if (t[j].startsWith("-")) continue;
          const a = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(t[j]);
          if (a) { if (reconfigures(a[1], this.cfg)) return reconf(a[1]); continue; }
          break;
        }
        return sub(j);
      }
      case "command":
        if (t[0] === "-v" || t[0] === "-V") return null;      // `command -v gpg` only looks it up
        return sub(skipOpts(t, []));
      case "screen": return sub(skipOpts(t, ["-S", "-c", "-e", "-h", "-p", "-T", "-t", "-L", "-Logfile"]));
      case "fd": case "fdfind": {
        const x = t.findIndex((a) => ["-x", "--exec", "-X", "--exec-batch"].includes(a));
        return x >= 0 ? sub(x + 1) : null;
      }
      case "builtin": case "nohup": case "pkexec": case "coproc": case "setsid": case "chronic": case "unbuffer":
      case "torsocks": case "proxychains": case "proxychains4": case "firejail": case "catchsegv":
        return sub(skipOpts(t, []));
      case "exec": return sub(skipOpts(t, ["-a"]));
      case "nice": return sub(skipOpts(t, ["-n", "--adjustment"]));
      case "ionice": return sub(skipOpts(t, ["-c", "-n", "-p", "-P", "-u"]));
      case "stdbuf": return sub(skipOpts(t, ["-i", "-o", "-e"]));
      case "chroot": return sub(skipOpts(t, ["--userspec", "--groups"]) + 1);
      case "strace": case "ltrace": return sub(skipOpts(t, ["-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-I", "-O", "-S", "-X", "-P"]));
      case "nsenter": case "unshare": case "systemd-run": case "runuser": case "setpriv":
        return sub(skipOpts(t, ["-t", "-u", "-g", "--unit", "-p", "--property", "--setenv", "-E", "--working-directory", "--uid", "--gid", "-M", "--machine", "--description"]));
      case "timeout": { const j = skipOpts(t, ["-s", "--signal", "-k", "--kill-after"]); return sub(j + 1); }
      case "flock": {
        const ci = t.findIndex((a) => a === "-c" || a === "--command");
        if (ci >= 0) return this.sub(t[ci + 1] ?? "");
        return sub(skipOpts(t, ["-w", "--timeout", "-E", "--conflict-exit-code"]) + 1);
      }
      case "xargs": return sub(skipOpts(t, ["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-lines", "--replace", "--eof"]));
      case "watch": return this.sub(t.slice(skipOpts(t, ["-n", "--interval", "-d", "--differences", "-q", "--equexit"])).join(" "));
      case "su": case "script": {
        for (let j = 0; j < t.length; j++) {
          if (t[j] === "-c" || t[j] === "--command") return this.sub(t[j + 1] ?? "");
          if (/^-[a-zA-Z]*c$/.test(t[j]) && !t[j].startsWith("--")) return this.sub(t[j + 1] ?? "");
          if (/^-[a-zA-Z]*c./.test(t[j]) && !t[j].startsWith("--")) return this.sub(t[j].slice(t[j].indexOf("c") + 1));
          if (t[j].startsWith("--command=")) return this.sub(t[j].slice(10));
        }
        return null;
      }
      case "eval": return this.sub(t.join(" "));
      case "function": return sub(1);                       // `function f { …; }`: the body
      case "passage": return passVerdict(t);                // pass on age
      case "gopass": {
        // gopass lists with ls/list/find/search (any args); everything else may print a value.
        const [sc] = t;
        if (!sc || ["ls", "list", "find", "search", "help", "version", "--help", "-h", "--version"].includes(sc)) return null;
        return { rule: "pass", what: `\`gopass ${sc}\` can print a stored value` };
      }
      case "gpg-sq": return gpgVerdict(t);
      case "git": {
        // Config values that git runs: `-c core.pager=…`, `-c alias.x=!…`, `git config alias.x '!…'`.
        for (let j = 0; j < t.length; j++) {
          const v = t[j] === "-c" ? (t[j + 1] ?? "").replace(/^[^=]*=/, "") : t[j].startsWith("!") ? t[j] : "";
          if (v) { const r = this.sub(v.replace(/^!/, "")); if (r) return r; }
        }
        return null;
      }
      case "uv": case "poetry": case "pipx": case "pdm": case "rye": case "hatch": {
        const run = t.indexOf("run");
        return run >= 0 ? sub(run + 1 + skipOpts(t.slice(run + 1), ["--with", "--python", "-p", "--env", "-e", "--from", "--spec"])) : null;
      }
      case "bunx": case "npx": case "pnpx": return sub(skipOpts(t, ["-p", "--package"]));
      case "tar": case "zip": case "7z": case "rsync": case "scp": case "cp": case "base64": case "xxd": case "od": case "gzip": case "zstd": case "xz":
        // Copying or archiving gpg's home hands over the (passphrase-protected) private keys.
        if (t.some((a) => resolve(a.replace(/^~(?=\/|$)/, this.cfg.home).replace(/^\$\{?HOME\}?(?=\/|$)/, this.cfg.home)) === this.cfg.gnupg)) {
          return { rule: "store-path", what: "it copies or archives gpg's home directory, which holds the private keys" };
        }
        break;
      case "alias":
        for (const a of t) {
          const m = /^[^=]+=([\s\S]*)$/.exec(a);
          const v = m ? this.sub(m[1]) : null; if (v) return v;
        }
        return null;
      case "ssh": {
        // Output of a remote command lands in this transcript too.
        const j = skipOpts(t, ["-b", "-B", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"]);
        return j + 1 < t.length ? this.sub(t.slice(j + 1).join(" ")) : null;
      }
      case "tmux": {
        const positional: string[] = [];
        for (let j = 1; j < t.length; j++) {
          if (["-s", "-n", "-t", "-c", "-x", "-y", "-F", "-e", "-l", "-N"].includes(t[j])) { j++; continue; }
          if (!t[j].startsWith("-")) positional.push(t[j]);
        }
        return positional.length ? this.sub(positional.join(" ")) : null;
      }
      case "parallel": {
        const j = skipOpts(t, ["-j", "--jobs", "-N", "-n", "-S", "--sshlogin", "--delay", "--timeout", "-a", "--arg-file", "--joblog", "--results", "--colsep", "-I"]);
        const end = t.indexOf(":::", j);
        return this.sub(t.slice(j, end < 0 ? t.length : end).join(" "));
      }
      case "busybox": return sub(0);
      case "pass": return passVerdict(t);
      case "gpg": case "gpg2": case "gpgsm": return gpgVerdict(t);
      case "gpgtar": return t.some((a) => a === "--decrypt" || a === "--list-archive" || /^-[a-zA-Z]*[dt]/.test(a) && !a.startsWith("--"))
        ? { rule: "gpg", what: "gpgtar --decrypt/--list-archive decrypts" } : null;
      case "gpg-connect-agent": {
        const all = [...t, ...(c?.heredocs.map((h) => h.body ?? "") ?? []), ...(c?.herestrings ?? [])].join("\n");
        if (/pkdecrypt|get_passphrase|preset_passphrase|export_key|keytocard|passwd/i.test(all) || t.includes("-r") || t.includes("--run")) {
          return { rule: "gpg", what: "gpg-connect-agent with a decrypt or passphrase command" };
        }
        return null;
      }
      case "gpg-agent": {
        const j = t.findIndex((a) => !a.startsWith("-"));
        return j >= 0 ? sub(j) : null;
      }
      case "find": {
        for (let j = 0; j < t.length; j++) {
          if (["-exec", "-execdir", "-ok", "-okdir"].includes(t[j])) {
            let e = j + 1;
            while (e < t.length && t[e] !== ";" && t[e] !== "+") e++;
            const v = this.command(args.slice(j + 1, e), null); if (v) return v;
            j = e;
          }
        }
        return null;
      }
    }

    if (SHELLS.has(name)) {
      for (let j = 0; j < t.length; j++) {
        const a = t[j];
        if (a === "--") break;
        if (["-o", "+o", "-O", "+O", "--rcfile", "--init-file"].includes(a)) { j++; continue; }   // option values
        if (a === "-c" || (/^-[a-zA-Z]+$/.test(a) && a.includes("c"))) return this.sub(t[j + 1] ?? "");
        if (!a.startsWith("-") && !a.startsWith("+")) break;   // a script file: not readable here
      }
      for (const body of bodies(c)) { const v = this.sub(body); if (v) return v; }
      return null;
    }

    if (INTERPRETER.test(name)) {
      // Inline code arrives as any argument (-c, -e, --eval, awk's program), or on stdin.
      for (const src of [...t, ...bodies(c)]) {
        if (interpreterReads(src)) return { rule: "interpreter", what: `${name} code that runs pass/gpg or opens the store` };
      }
    }

    // `… -- <command>`: e.g. `cred exec name -- pass show x`
    const dd = t.indexOf("--");
    if (dd >= 0 && dd + 1 < t.length) return sub(dd + 1);
    return null;
  }
}

class Denied extends Error {
  constructor(public verdict: Verdict) { super(verdict.what); }
}

function blank(): Simple { return { words: [], redirs: [], heredocs: [], herestrings: [] }; }

// What a command reads on stdin, as far as we can tell.
function bodies(c: Simple | null): string[] {
  if (!c) return [];
  return [...c.heredocs.map((h) => h.body ?? ""), ...c.herestrings, ...writes(c.from)];
}

// What a command upstream in a pipe writes, when that is knowable.
function writes(c: Simple | undefined): string[] {
  if (!c) return [];
  const printed = isEcho(c) ? [unescape(c.words.slice(1).map((w) => w.text).filter((w) => !/^-[neE]+$/.test(w)).join(" "))] : [];
  return [...bodies(c), ...printed];
}

// printf and echo -e escapes, so `printf '\x70ass show x' | sh` reads as what sh receives.
function unescape(t: string): string {
  return t.replace(/\\(x[0-9a-fA-F]{1,2}|0?[0-7]{1,3}|[ntr\\])/g, (_m, e: string) => {
    if (e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
    return ({ n: "\n", t: "\t", r: "\r", "\\": "\\" } as Record<string, string>)[e];
  });
}

function isEcho(c: Simple): boolean {
  const n = c.words[0]?.text;
  return n === "echo" || n === "printf";
}

const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "yash", "posh", "rbash", "csh", "tcsh", "elvish", "nu", "pwsh"]);
const INTERPRETER = /^(python[\d.]*|pypy[\d.]*|node|nodejs|bun|deno|perl[\d.]*|ruby[\d.]*|php[\d.]*|lua[\d.]*|Rscript|tclsh|awk|gawk|mawk|osascript)$/;

function interpreterReads(src: string): boolean {
  // A quoted "pass" or "gpg" counts as an argv element: ("pass", ['pass', , `gpg`. Not status === "pass".
  return /[(\[,]\s*(["'`])pass\1/.test(src)
    || /\bpass\s+(show|ls|list|grep|edit|otp|git|-c|--clip|insert|generate)\b/.test(src)
    || /(["'`])pass\s/.test(src)
    || gpgDecryptLine(src)
    || (/gnupg|gpgme/i.test(src) && /decrypt/i.test(src))
    || /[(\[,]\s*(["'`])gpg2?\1/.test(src)
    || /password-store|PASSWORD_STORE_DIR|private-keys-v1\.d|secring\.gpg/.test(src);
}

// The broker's locations and everything that steers pass (its extensions run code).
const BROKER_VARS = new Set(["CRED_MANIFEST", "CRED_STORE_DIR", "CRED_STATE_DIR", "CRED_AUDIT_DIR"]);
// Linear: one look per line from its first "gpg" (a per-token regex is quadratic on long input).
function gpgDecryptLine(src: string): boolean {
  return src.split("\n").some((line) => {
    const i = line.search(/\bgpg/);
    return i >= 0 && /--?dec|\s-[a-zA-Z]*d\b/.test(line.slice(i));
  });
}

function reconfigures(name: string, cfg: GuardConfig): boolean {
  return BROKER_VARS.has(name) || name.startsWith("PASSWORD_STORE_") || cfg.extraVars.includes(name);
}
function reconf(name: string): Verdict {
  return { rule: "reconfigure", what: `setting ${name} would point the broker or pass somewhere else; that is the user's configuration` };
}

// Index of the first non-option word. Options listed in `withArg` consume the next word.
function skipOpts(t: string[], withArg: string[]): number {
  let j = 0;
  for (; j < t.length; j++) {
    const a = t[j];
    if (a === "--") return j + 1;
    if (!a.startsWith("-") || a === "-") break;
    if (withArg.includes(a) || (/^-[A-Za-z]{2,}$/.test(a) && withArg.includes("-" + a[a.length - 1]))) j++;
  }
  return j;
}

// pass: `ls`, `list` and `show` are one function in pass, so `pass ls foo` prints foo.
// Only name listings are allowed: bare pass, ls/list with no argument, find/search, help, version.
function passVerdict(t: string[]): Verdict | null {
  if (t.length === 0) return null;
  const [subcmd, ...rest] = t;
  if ((subcmd === "ls" || subcmd === "list") && rest.length === 0) return null;
  if (subcmd === "find" || subcmd === "search") return null;
  if (["help", "version", "--help", "-h", "--version"].includes(subcmd)) return null;
  return { rule: "pass", what: `\`pass ${subcmd}\` can print a stored value` };
}

// gpg: allowed only with a command option that cannot decrypt. No command option means gpg
// guesses, and on an encrypted file or stdin it decrypts, so that is denied too. gpg accepts
// unambiguous prefixes of long options (`--dec`), so a prefix of a dangerous option is dangerous.
const GPG_DANGER = [
  "decrypt", "decrypt-files", "multifile", "export-secret-keys", "export-secret-subkeys",
  "export-secret-key-p12", "export-secret-key-raw", "options", "command-fd", "command-file",
  "passphrase", "passphrase-fd", "passphrase-file", "passphrase-repeat", "pinentry-mode",
  "list-packets", "show-session-key", "override-session-key", "override-session-key-fd",
  "card-edit", "edit-card", "edit-key", "change-passphrase", "passwd", "server", "gpgconf-test",
];
const GPG_SAFE = [
  "list-keys", "list-public-keys", "list-secret-keys", "list-sigs", "list-signatures", "check-sigs",
  "check-signatures", "fingerprint", "version", "help", "dump-options", "import", "export",
  "recv-keys", "receive-keys", "refresh-keys", "search-keys", "fetch-keys", "locate-keys",
  "locate-external-keys", "verify", "verify-files", "encrypt", "encrypt-files", "sign",
  "clear-sign", "clearsign", "detach-sign", "symmetric", "list-config", "gpgconf-list",
  "card-status", "export-ownertrust", "import-ownertrust", "update-trustdb", "check-trustdb",
  "quick-generate-key", "quick-gen-key", "generate-key", "gen-key", "full-generate-key",
  "full-gen-key", "print-md", "gen-random", "warranty", "export-ssh-key",
];
const GPG_SHORT_ARG = new Set(["r", "u", "o", "z", "R", "f", "N"]);   // take a value
const GPG_SHORT_CMD = new Set(["k", "K", "e", "s", "b", "c", "h"]);
const GPG_LONG_ARG = new Set([
  "recipient", "local-user", "output", "homedir", "keyserver", "default-key", "trust-model",
  "hidden-recipient", "encrypt-to", "keyring", "secret-keyring", "compress-level", "cipher-algo",
  "digest-algo", "set-filename", "comment", "trusted-key", "status-fd", "logger-fd",
  "attribute-fd", "max-output", "keyid-format", "display-charset", "default-recipient",
  "list-options", "verify-options", "export-options", "import-options", "auto-key-locate",
  "agent-program", "dirmngr-program", "faked-system-time", "s2k-mode", "s2k-cipher-algo",
]);

function gpgVerdict(t: string[]): Verdict | null {
  let safe = false;
  for (let j = 0; j < t.length; j++) {
    const a = t[j];
    if (a === "--") break;
    if (a.startsWith("--")) {
      const name = a.slice(2).split("=")[0];
      if (GPG_DANGER.includes(name) || (name.length >= 3 && GPG_DANGER.some((d) => d.startsWith(name)) && !GPG_SAFE.includes(name))) {
        return { rule: "gpg", what: `gpg --${name} can decrypt or expose secret material` };
      }
      if (GPG_SAFE.includes(name)) { safe = true; continue; }
      const prefixed = GPG_SAFE.filter((s) => s.startsWith(name));
      if (name.length >= 3 && prefixed.length === 1) { safe = true; continue; }
      if (GPG_LONG_ARG.has(name) && !a.includes("=")) j++;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      for (let q = 1; q < a.length; q++) {
        const ch = a[q];
        if (ch === "d") return { rule: "gpg", what: "gpg -d decrypts" };
        if (GPG_SHORT_CMD.has(ch)) safe = true;
        if (GPG_SHORT_ARG.has(ch)) { if (q === a.length - 1) j++; break; }
      }
    }
  }
  return safe ? null : { rule: "gpg", what: "gpg without a listing/encrypting command option decrypts its input by default" };
}

// ───────────────────────── hook entry ─────────────────────────

function message(v: Verdict, cfg: GuardConfig): string {
  return `cred-broker guard (${v.rule}): blocked because ${v.what}. ` +
    `Use the broker, which hands the value to a command without showing it: ` +
    `\`${cfg.brokerCmd} exec <name> -- <command…>\` (names: \`${cfg.brokerCmd} list\`). ` +
    `If the user needs this command itself, they can run it in their own terminal.`;
}

export async function runHook(stdin: string, cfg: GuardConfig = defaultConfig()): Promise<string> {
  let input: { tool_name?: string; tool_input?: Record<string, unknown>; cwd?: string };
  try { input = JSON.parse(stdin); } catch { return ""; }        // not hook input: fail open
  if (!input || typeof input !== "object") return "";
  let v: Verdict | null;
  try {
    v = inspectTool(String(input.tool_name ?? ""), input.tool_input ?? {}, input.cwd, cfg);
  } catch (err) {
    v = err instanceof Denied ? err.verdict : { rule: "error", what: `the guard failed while checking it (${(err as Error).message})` };
  }
  if (!v) return "";
  return JSON.stringify({
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: message(v, cfg) },
  });
}

export async function main(): Promise<number> {
  const out = await runHook(await Bun.stdin.text());
  if (out) console.log(out);
  return 0;
}

if (import.meta.main) process.exitCode = await main();
