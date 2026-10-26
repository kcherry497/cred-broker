// End-to-end tests for cred.ts against a throwaway GPG key, password store, manifest and audit dir.
// Every path the broker could touch (HOME, GNUPGHOME, the store, CRED_* and XDG dirs) is under a temp
// dir, checked before anything runs, so the real store, agent and gpg-agent.conf are never used.
//   bun test test/cred.test.ts
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

// CRED_UNDER_TEST runs the same suite against another entry point, e.g. an installed wrapper.
const CRED = process.env.CRED_UNDER_TEST ?? join(import.meta.dir, "..", "src", "cred.ts");
// A wrapper may pin the CRED_* locations (and should ignore inherited ones), so tests that move
// them are for the generic entry point only.
const generic = !process.env.CRED_UNDER_TEST;
const BUN = process.execPath;
const REAL_CONF = join(homedir(), ".gnupg", "gpg-agent.conf");
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "cred-test-")));
const env: Record<string, string> = {
  PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C.UTF-8",
  HOME: join(tmp, "home"), GNUPGHOME: join(tmp, "gnupg"),
  PASSWORD_STORE_DIR: join(tmp, "store"),
  // A wrapper that derives these locations itself must map them onto these paths (see CRED_UNDER_TEST).
  CRED_MANIFEST: join(tmp, "config", "manifest.yaml"),
  CRED_STATE_DIR: join(tmp, "state"),
  CRED_AUDIT_DIR: join(tmp, "state"),
  XDG_CONFIG_HOME: join(tmp, "xdg-config"), XDG_STATE_HOME: join(tmp, "xdg-state"),
  CRED_RELOCK: "detached", CLAUDE_CODE_SESSION_ID: "test-session-42",
};
if (process.env.XDG_RUNTIME_DIR) env.XDG_RUNTIME_DIR = process.env.XDG_RUNTIME_DIR;
const CONF = join(env.GNUPGHOME, "gpg-agent.conf");
const STATE = join(env.CRED_STATE_DIR, "unlock-state.json");
const MARK = "# cred-managed: written by cred unlock, restored by cred lock";

const V = {
  basic: "hunter2-Correct-Horse_9f8e7d",
  weird: `p@ss w/rd+$&'"\\%é€😀-long-enough`,
  multi: "-----BEGIN TEST KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\nCyZ9q8m1wXkPzT0bQ7vLrN5sJ3hF\n-----END TEST KEY-----",
  crlf: "crlf-value-123456",
  short: "abc",
};
const b64 = (s: string) => Buffer.from(s).toString("base64");
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let realConfHash = "";

function sh(cmd: string[], input?: string) {
  const r = Bun.spawnSync(cmd, { env, stdin: input === undefined ? "ignore" : Buffer.from(input), stdout: "pipe", stderr: "pipe" });
  if (r.exitCode !== 0) throw new Error(`${cmd.join(" ")} failed: ${r.stderr.toString()}`);
  return r.stdout.toString();
}

// `over` adds or (with undefined) removes env vars for one run.
async function cred(args: string[], over: Record<string, string | undefined> = {}) {
  const e: Record<string, string> = { ...env };
  for (const [k, v] of Object.entries(over)) v === undefined ? delete e[k] : (e[k] = v);
  const p = Bun.spawn([BUN, CRED, ...args], { env: e, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).arrayBuffer(), new Response(p.stderr).text(), p.exited]);
  return { out: Buffer.from(out), text: Buffer.from(out).toString("utf8"), err, code };
}
const ex = (name: string, script: string) => cred(["exec", name, "--", "sh", "-c", script]);
const exBun = (name: string, js: string) => cred(["exec", name, "--", BUN, "-e", js]);

// Each stdout chunk with the time it arrived.
async function timed(args: string[]) {
  const t0 = Date.now();
  const p = Bun.spawn([BUN, CRED, ...args], { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  const chunks: [number, string][] = [];
  const reader = p.stdout.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push([Date.now() - t0, Buffer.from(value).toString()]);
  }
  await p.exited;
  return chunks;
}

const auditText = () => {
  const day = new Date().toISOString().slice(0, 10);
  const f = join(env.CRED_AUDIT_DIR, day.slice(0, 4), day.slice(5, 7), `cred-${day.replace(/-/g, "")}.jsonl`);
  return existsSync(f) ? readFileSync(f, "utf8") : "";
};
const audit = () => auditText().trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const unlockViaPty = (hours: string) =>
  Bun.spawnSync(["script", "-qec", `"${BUN}" "${CRED}" unlock ${hours}`, "/dev/null"], { env, stdout: "pipe", stderr: "pipe" });
const state = () => (existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : null);

beforeAll(() => {
  for (const k of ["HOME", "GNUPGHOME", "PASSWORD_STORE_DIR", "CRED_MANIFEST", "CRED_STATE_DIR", "CRED_AUDIT_DIR", "XDG_CONFIG_HOME", "XDG_STATE_HOME"]) {
    if (!env[k].startsWith(tmp + "/") || env[k].startsWith(homedir() + "/")) throw new Error(`refusing: ${k}=${env[k]} is not a temp path`);
  }
  realConfHash = existsSync(REAL_CONF) ? sha(readFileSync(REAL_CONF)) : "absent";
  mkdirSync(env.HOME, { recursive: true });
  mkdirSync(env.GNUPGHOME, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(env.CRED_MANIFEST), { recursive: true });
  mkdirSync(env.CRED_STATE_DIR, { recursive: true });
  sh(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "Cred Test <cred-test@example.invalid>", "default", "default", "never"]);
  const fpr = sh(["gpg", "--list-keys", "--with-colons"]).split("\n").find((l) => l.startsWith("fpr:"))!.split(":")[9];
  sh(["pass", "init", fpr]);
  for (const [k, v] of Object.entries(V)) sh(["pass", "insert", "--multiline", "--force", `test/${k}`], k === "crlf" ? v + "\r\n" : v + "\n");
  const manifest = Object.fromEntries(Object.keys(V).map((k) => [k, {
    describes: `test ${k}`, pass_path: `test/${k}`, env: `CRED_${k.toUpperCase()}`, ...(k === "multi" ? { format: "full" } : {}),
  }]));
  writeFileSync(env.CRED_MANIFEST, JSON.stringify(manifest, null, 2));
}, 60_000);

afterAll(() => {
  for (const e of audit()) if (e.event_type === "unlock") Bun.spawnSync(["pkill", "-f", `relock ${e.window_id}`]);
  Bun.spawnSync(["gpgconf", "--kill", "gpg-agent"], { env });
  rmSync(tmp, { recursive: true, force: true });
});

describe("output filtering", () => {
  test("raw value on stdout", async () => {
    const r = await ex("basic", 'printf "%s\\n" "$CRED_BASIC"');
    expect(r.text).toBe("[cred:basic]\n");
    expect(r.err).toContain("filtered 1 occurrence");
    expect(r.code).toBe(0);
  });

  test("raw value on stderr", async () => {
    const r = await ex("basic", 'printf "%s\\n" "$CRED_BASIC" >&2');
    expect(r.err).toContain("[cred:basic]");
    expect(r.err).not.toContain(V.basic);
  });

  test("base64, with and without the trailing newline echo adds", async () => {
    for (const script of ['printf %s "$CRED_BASIC" | base64 -w0', 'echo "$CRED_BASIC" | base64']) {
      const r = await ex("basic", script);
      expect(r.text).toContain("[cred:basic]");
      expect(r.text).not.toContain(b64(V.basic).slice(4, -4));
    }
  });

  test("Basic auth at every alignment", async () => {
    for (const prefix of ["", "a:", "ab:", "abc:", "user:"]) {
      const r = await ex("basic", `printf %s "${prefix}$CRED_BASIC" | base64 -w0`);
      expect(r.text).toContain("[cred:basic]");
      expect(r.text).not.toContain(b64(prefix + V.basic).slice(8, 24));
    }
  });

  test("curl -v style Authorization header on stderr", async () => {
    const r = await ex("basic", 'printf "> Authorization: Basic %s\\n" "$(printf %s "admin:$CRED_BASIC" | base64 -w0)" >&2');
    expect(r.err).toContain("> Authorization: Basic ");
    expect(r.err).toContain("[cred:basic]");
    expect(r.err).not.toContain(b64("admin:" + V.basic).slice(8, 24));
  });

  test("URL-encoded, JSON, Python-style JSON", async () => {
    expect((await exBun("weird", "console.log(encodeURIComponent(process.env.CRED_WEIRD))")).text).toBe("[cred:weird]\n");
    expect((await exBun("weird", "console.log(JSON.stringify(process.env.CRED_WEIRD))")).text).toBe('"[cred:weird]"\n');
    const py = 'console.log(JSON.stringify(process.env.CRED_WEIRD).replace(/[\\u007f-\\uffff]/g, (c) => "\\\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")))';
    expect((await exBun("weird", py)).text).toBe('"[cred:weird]"\n');
  });

  test("bash -x trace", async () => {
    const r = await cred(["exec", "weird", "--", "bash", "-xc", "x=$CRED_WEIRD; :"]);
    expect(r.err).toContain("[cred:weird]");
    expect(r.err).not.toContain("w/rd+$&");
  });

  test("value split across writes with a pause", async () => {
    const js = 'const v=process.env.CRED_BASIC; process.stdout.write("A"+v.slice(0,10)); await Bun.sleep(400); process.stdout.write(v.slice(10)+"B\\n")';
    expect((await exBun("basic", js)).text).toBe("A[cred:basic]B\n");
  });

  test("a 2-byte prefix is released after silence, the rest is still filtered", async () => {
    const js = 'const v=process.env.CRED_BASIC; process.stdout.write(v.slice(0,2)); await Bun.sleep(400); process.stdout.write(v.slice(2)+"\\n")';
    const r = await exBun("basic", js);
    expect(r.text).toBe(V.basic.slice(0, 2) + "[cred:basic]\n");
  });

  test("a prompt ending in the value's first byte is not held", async () => {
    // V.basic starts with "h"
    const chunks = await timed(["exec", "basic", "--", BUN, "-e", 'process.stdout.write("Token? h"); await Bun.sleep(1500); process.stdout.write("\\n")']);
    const first = chunks.find(([, s]) => s.includes("h"))!;
    const last = chunks[chunks.length - 1];
    expect(last[0] - first[0]).toBeGreaterThan(1000);
  }, 15_000);

  test("lines stream as they are written", async () => {
    const chunks = await timed(["exec", "basic", "--", "sh", "-c", "echo one; sleep 1; echo two"]);
    const one = chunks.find(([, s]) => s.includes("one"))!;
    const two = chunks.find(([, s]) => s.includes("two"))!;
    expect(two[0] - one[0]).toBeGreaterThan(700);
  }, 15_000);

  test("binary output passes byte for byte", async () => {
    const raw = join(tmp, "bin.raw");
    const r = await ex("basic", `head -c 3000000 /dev/urandom | tee "${raw}"`);
    expect(sha(r.out)).toBe(sha(readFileSync(raw)));
  }, 20_000);

  test("50 MB through a slow reader keeps every byte", () => {
    const t0 = Date.now();
    const r = Bun.spawnSync(["sh", "-c", `"${BUN}" "${CRED}" exec basic -- head -c 50000000 /dev/zero | (sleep 1; sha256sum)`], { env, stdout: "pipe" });
    console.log(`  50 MB in ${Date.now() - t0} ms (includes a 1 s reader delay)`);
    expect(r.stdout.toString().split(" ")[0]).toBe(sha(Buffer.alloc(50_000_000)));
  }, 60_000);

  test("a reader that closes early (| head) does not hang or crash", () => {
    const t0 = Date.now();
    const r = Bun.spawnSync(["bash", "-c", `"${BUN}" "${CRED}" exec basic -- yes | head -c 10; echo " rc=\${PIPESTATUS[0]}"`], { env, stdout: "pipe", stderr: "pipe" });
    expect(Date.now() - t0).toBeLessThan(10_000);
    expect(r.stdout.toString()).toBe("y\ny\ny\ny\ny\n rc=141\n");
  }, 20_000);
});

describe("process handling", () => {
  test("exit code passes through", async () => {
    expect((await ex("basic", "exit 7")).code).toBe(7);
  });

  test("a child killed by a signal is not reported as success", async () => {
    expect((await ex("basic", "kill -TERM $$")).code).toBe(143);
  });

  test("SIGTERM to the broker reaches the child", async () => {
    const pidFile = join(tmp, "child.pid");
    const p = Bun.spawn([BUN, CRED, "exec", "basic", "--", "sh", "-c", `echo $$ > "${pidFile}"; exec sleep 30`], { env, stdin: "ignore", stdout: "ignore", stderr: "ignore" });
    for (let i = 0; i < 100 && !existsSync(pidFile); i++) await sleep(50);
    const pid = Number(readFileSync(pidFile, "utf8"));
    p.kill("SIGTERM");
    expect(await p.exited).toBe(143);
    await sleep(100);
    expect(() => process.kill(pid, 0)).toThrow();
  }, 10_000);

  test("a missing command fails with 127 instead of hanging", async () => {
    const r = await cred(["exec", "basic", "--", "/nonexistent/cmd"]);
    expect(r.code).toBe(127);
    expect(r.err).toContain("cannot run");
  }, 10_000);

  test("everything after the first -- is the command, later -- included", async () => {
    expect((await cred(["exec", "basic", "--", "echo", "hi"])).text).toBe("hi\n");
    expect((await cred(["exec", "basic", "--", "echo", "--", "hi"])).text).toBe("-- hi\n");
  });

  test("env dumpers are still refused", async () => {
    const r = await cred(["exec", "basic", "--", "env"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("refusing");
  });

  test("a value under 4 bytes is not filtered, and says so", async () => {
    const r = await ex("short", 'printf "%s\\n" "$CRED_SHORT"');
    expect(r.text).toBe("abc\n");
    expect(r.err).toContain("NOT filtered");
  });
});

describe("value formats", () => {
  test("format: full injects every line and filters the whole value and each long line", async () => {
    expect((await ex("multi", 'printf "%s" "$CRED_MULTI" | wc -l')).text.trim()).toBe("3");
    expect((await ex("multi", 'printf "%s\\n" "$CRED_MULTI"')).text).toBe("[cred:multi]\n");
    expect((await ex("multi", 'printf "%s\\n" "$CRED_MULTI" | sed -n 2p')).text).toBe("[cred:multi]\n");
  });

  test("the default format drops a trailing carriage return", async () => {
    expect((await exBun("crlf", "console.log(process.env.CRED_CRLF.length)")).text).toBe("17\n");
  });
});

describe("audit", () => {
  test("records carry the session, full argv, cwd, and a done record; never the value", async () => {
    const r = await cred(["exec", "basic", "--", "echo", V.basic]);
    expect(r.text).toBe("[cred:basic]\n");
    const ev = audit();
    expect(ev.length).toBeGreaterThan(10);
    expect(ev.every((e) => e.session === "test-session-42")).toBe(true);
    const exec = ev.filter((e) => e.event_type === "exec").at(-1);
    expect(exec.argv).toEqual(["echo", "[cred:basic]"]);
    expect(typeof exec.cwd).toBe("string");
    expect(typeof exec.ppid).toBe("number");
    const done = ev.filter((e) => e.event_type === "exec_done").at(-1);
    expect(done).toMatchObject({ key: "basic", exit: 0, redactions: 1 });
    expect(typeof done.duration_ms).toBe("number");
    const text = auditText();
    for (const v of [V.basic, V.weird, V.crlf]) expect(text).not.toContain(v);
  });

  test("without a Claude session ID, records the logged-in user: $USER first", async () => {
    const r = await cred(["exec", "basic", "--", "true"], { CLAUDE_CODE_SESSION_ID: undefined, USER: "audit-user" });
    expect(r.code).toBe(0);
    const ev = audit().slice(-2);
    expect(ev.map((e) => e.event_type)).toEqual(["exec", "exec_done"]);
    expect(ev.every((e) => e.session === "audit-user")).toBe(true);
  });

  test("without $USER or $LOGNAME, falls back to id -un (NSS)", async () => {
    const r = await cred(["exec", "basic", "--", "true"], { CLAUDE_CODE_SESSION_ID: undefined, USER: undefined, LOGNAME: undefined });
    expect(r.code).toBe(0);
    const who = Bun.spawnSync(["id", "-un"]).stdout.toString().trim();
    const ev = audit().slice(-2);
    expect(ev.map((e) => [e.event_type, e.session])).toEqual([["exec", who], ["exec_done", who]]);
  });
});

describe("locations and identity", () => {
  const day = () => new Date().toISOString().slice(0, 10);
  const dayFile = (dir: string) => join(dir, day().slice(0, 4), day().slice(5, 7), `cred-${day().replace(/-/g, "")}.jsonl`);
  const noCredPaths = { CRED_MANIFEST: undefined, CRED_STATE_DIR: undefined, CRED_AUDIT_DIR: undefined };

  test.skipIf(!generic)("with no CRED_* paths set, the manifest and audit log follow XDG", async () => {
    const dir = join(env.XDG_CONFIG_HOME, "cred-broker");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "manifest.yaml"), JSON.stringify({ xdg: { describes: "x", pass_path: "test/basic", env: "XDG_VAL" } }));
    const r = await cred(["exec", "xdg", "--", "sh", "-c", 'printf %s "$XDG_VAL" | wc -c'], noCredPaths);
    expect(r.text.trim()).toBe(String(V.basic.length));
    const log = dayFile(join(env.XDG_STATE_HOME, "cred-broker", "audit"));
    expect(existsSync(log)).toBe(true);
    expect(readFileSync(log, "utf8")).toContain('"key":"xdg"');
  });

  test("CRED_STORE_DIR is the store pass reads, whatever PASSWORD_STORE_DIR says", async () => {
    const r = await cred(["exec", "basic", "--", "true"], { CRED_STORE_DIR: env.PASSWORD_STORE_DIR, PASSWORD_STORE_DIR: join(tmp, "no-such-store") });
    expect(r.code).toBe(0);
  });

  test("CRED_SESSION_ID names the session for any agent", async () => {
    await cred(["exec", "basic", "--", "true"], { CRED_SESSION_ID: "other-agent-7" });
    expect(audit().slice(-2).every((e) => e.session === "other-agent-7")).toBe(true);
  });

  test("messages name the command that was actually run", async () => {
    const r = await cred(["set", "basic"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain(`${CRED} set basic`);
    expect(r.err).not.toContain("~/.claude");
  });
});

describe("terminal echo", () => {
  const after = 'stty -a | tr " ;" "\\n\\n" | grep -qx echo && echo AFTER-ECHO-ON || echo AFTER-ECHO-OFF';
  const setViaPty = (path: string, prefix = "") => {
    const r = Bun.spawnSync([Bun.which("script")!, "-qec", `${prefix}"${BUN}" "${CRED}" set basic; echo EXIT=$?; ${after}`, "/dev/null"],
      { env: { ...env, PATH: path }, stdout: "pipe", stderr: "pipe", timeout: 10_000 });
    expect(r.exitCode).toBe(0);
    const out = r.stdout.toString();
    expect(out).toContain("AFTER-ECHO-ON");
    return out;
  };

  // A stand-in for pass reports what the terminal looks like when the prompt would appear.
  test("set turns echo off before prompting and puts it back afterwards", () => {
    const bin = join(tmp, "fake-bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "pass"), '#!/bin/sh\nstty -a | tr " ;" "\\n\\n" | grep -qx -- -echo && echo CHILD-SAW-ECHO-OFF || echo CHILD-SAW-ECHO-ON\n', { mode: 0o755 });
    const out = setViaPty(`${bin}:${env.PATH}`);
    expect(out).toContain("CHILD-SAW-ECHO-OFF");
  });

  test("set returns 127 and restores echo when pass is missing", () => {
    const bin = join(tmp, "missing-pass-bin");
    mkdirSync(bin);
    for (const cmd of ["sh", "stty", "tr", "grep"]) symlinkSync(Bun.which(cmd)!, join(bin, cmd));
    const out = setViaPty(bin);
    expect(out).toContain("EXIT=127");
    expect(out).toContain("cred: cannot run 'pass':");
  }, 15_000);

  test("set returns 130 and restores echo on Ctrl-C", () => {
    const bin = join(tmp, "sigint-pass-bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "pass"), '#!/bin/sh\nkill -INT 0\nsleep 1\n', { mode: 0o755 });
    const out = setViaPty(`${bin}:${env.PATH}`, 'trap "echo SH-INT" INT; ');
    expect(out).toContain("SH-INT");
    expect(out).toContain("EXIT=130");
  });

  test("set reapplies echo-off on SIGCONT and restores echo afterwards", () => {
    const bin = join(tmp, "sigcont-pass-bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "pass"), '#!/bin/sh\nstty echo\nkill -CONT $PPID\ni=0\nwhile [ "$i" -lt 20 ]; do\n  if stty -a | tr " ;" "\\n\\n" | grep -qx -- -echo; then echo REAPPLIED; exit 0; fi\n  sleep 0.1\n  i=$((i + 1))\ndone\necho NOT-REAPPLIED\n', { mode: 0o755 });
    const out = setViaPty(`${bin}:${env.PATH}`);
    expect(out).toMatch(/^REAPPLIED\r?$/m);
  });
});

describe("doctor", () => {
  const claudeDir = join(tmp, "claude-config");
  const doctor = (over: Record<string, string | undefined> = {}) => cred(["doctor"], { CLAUDE_CONFIG_DIR: claudeDir, ...over });
  const settings = (hooks: unknown) => { mkdirSync(claudeDir, { recursive: true }); writeFileSync(join(claudeDir, "settings.json"), JSON.stringify({ hooks })); };

  test("a working setup passes, with version, platform and store", async () => {
    const r = await doctor();
    expect(r.code).toBe(0);
    expect(r.text).toMatch(/^cred-broker \S+ \(source [0-9a-f]{12}\)/);
    expect(r.text).toMatch(/ok {4}platform|warn {2}platform/);
    expect(r.text).toContain("ok    gpg");
    expect(r.text).toContain("ok    pass");
    expect(r.text).toContain("ok    password store");
    expect(r.text).toContain("ok    manifest");
    expect(r.text).toContain("warn  no Claude Code settings found");
  });

  test("a missing store fails and prints the commands that create one", async () => {
    const r = await doctor({ CRED_STORE_DIR: join(tmp, "empty-store") });
    expect(r.code).toBe(1);
    expect(r.text).toContain("FAIL  no password store");
    expect(r.text).toContain("gpg --quick-generate-key");
    expect(r.text).toContain("pass init");
  });

  test.skipIf(!generic)("a manifest that does not parse fails", async () => {
    const bad = join(tmp, "bad.yaml");
    writeFileSync(bad, "a: [unclosed\n");
    const r = await doctor({ CRED_MANIFEST: bad });
    expect(r.code).toBe(1);
    expect(r.text).toContain("FAIL  manifest does not parse");
  });

  test.skipIf(!generic)("entries not yet stored are listed with the command that stores them", async () => {
    const m = join(tmp, "unstored.yaml");
    writeFileSync(m, JSON.stringify({ later: { describes: "x", pass_path: "test/not-there", env: "LATER" } }));
    const r = await doctor({ CRED_MANIFEST: m });
    expect(r.text).toContain("warn  'later' is not stored yet");
    expect(r.text).toContain("set later");
  });

  test("hook registration: missing, partial and complete", async () => {
    settings({});
    expect((await doctor()).text).toContain("warn  guard hook not registered");
    const guard = `"${BUN}" "${join(import.meta.dir, "..", "src", "guard.ts")}"`;
    settings({ PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: guard }] }] });
    expect((await doctor()).text).toContain("does not cover Read, Grep, Glob");
    settings({
      PreToolUse: [{ matcher: "Bash|Read|Grep|Glob", hooks: [{ type: "command", command: guard }] }],
      SessionStart: [{ hooks: [{ type: "command", command: "bun /x/src/session-start.ts" }] }],
    });
    const r = await doctor();
    expect(r.text).toContain("ok    guard hook registered");
    expect(r.text).toContain("ok    guard hook works");
    expect(r.text).toContain("ok    session-start hook");
    rmSync(join(claudeDir, "settings.json"));
  });

  test("a registered guard that does not work fails", async () => {
    settings({ PreToolUse: [{ matcher: "Bash|Read|Grep|Glob", hooks: [{ type: "command", command: `"${BUN}" /nonexistent/guard.ts` }] }] });
    const r = await doctor();
    expect(r.code).toBe(1);
    expect(r.text).toContain("FAIL  guard hook did not deny a probe");
    rmSync(join(claudeDir, "settings.json"));
  });

  test("exec requires the -- separator", async () => {
    const r = await cred(["exec", "basic", "printf", "x"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("Usage: exec <name> -- <command...>");
    expect(r.text).toBe("");
  });

  test("help lists doctor and version", async () => {
    const r = await cred(["--help"]);
    expect(r.code).toBe(0);
    expect(r.err).toContain("doctor");
    expect(r.err).toContain("version");
  });
});

describe("unlock and lock", () => {
  const userConf = "allow-loopback-pinentry\ndefault-cache-ttl 300\nmax-cache-ttl 900\n";

  test("unlock marks its TTL lines and saves the user's; a second unlock keeps the user's", () => {
    writeFileSync(CONF, userConf);
    expect(unlockViaPty("0.01").exitCode).toBe(0);
    let conf = readFileSync(CONF, "utf8");
    expect(conf).toContain(MARK);
    expect(conf).toContain("default-cache-ttl 36\n");
    expect(conf).toContain("max-cache-ttl 36\n");
    expect(conf).toContain("allow-loopback-pinentry");
    const first = state();
    expect(first.ttl_restore).toEqual({ "default-cache-ttl": "300", "max-cache-ttl": "900" });
    expect(unlockViaPty("0.01").exitCode).toBe(0);
    expect(state().ttl_restore).toEqual({ "default-cache-ttl": "300", "max-cache-ttl": "900" });
    expect(state().window_id).not.toBe(first.window_id);
    conf = readFileSync(CONF, "utf8");
    expect(conf.split("\n").filter((l) => l === MARK).length).toBe(1);
  }, 30_000);

  test("lock restores the user's TTL lines and clears the state", async () => {
    const r = await cred(["lock"]);
    expect(r.code).toBe(0);
    expect(readFileSync(CONF, "utf8")).toBe(userConf);
    expect(state()).toBeNull();
    expect(audit().filter((e) => e.event_type === "lock").at(-1).ttl_restored).toBe(true);
  });

  test("the expiry relock restores the TTL on its own", async () => {
    expect(unlockViaPty("0.001").exitCode).toBe(0);   // 4 s window
    expect(readFileSync(CONF, "utf8")).toContain(MARK);
    await sleep(7000);
    expect(readFileSync(CONF, "utf8")).toBe(userConf);
    expect(state()).toBeNull();
    expect(audit().some((e) => e.event_type === "relock")).toBe(true);
  }, 30_000);

  test("an old window's relock does not cut a newer window short", async () => {
    expect(unlockViaPty("0.001").exitCode).toBe(0);   // 4 s
    const old = state().window_id;
    expect(unlockViaPty("0.01").exitCode).toBe(0);    // 36 s, replaces it
    const current = state().window_id;
    await sleep(7000);
    expect(state()?.window_id).toBe(current);
    expect(readFileSync(CONF, "utf8")).toContain(MARK);
    expect(audit().some((e) => e.event_type === "relock_skipped" && e.window_id === old)).toBe(true);
    expect((await cred(["lock"])).code).toBe(0);
    expect(readFileSync(CONF, "utf8")).toBe(userConf);
  }, 30_000);

  test("the real gpg-agent.conf was never touched", () => {
    expect(existsSync(REAL_CONF) ? sha(readFileSync(REAL_CONF)) : "absent").toBe(realConfHash);
  });
});
