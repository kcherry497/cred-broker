// Decision table and hook protocol for src/guard.ts. Each row is a command an agent might run and
// whether the guard must deny it. Adversarial cases live in guard.adversarial.test.ts.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { defaultConfig, inspectCommand, inspectTool } from "../src/guard.ts";

const cfg = defaultConfig({ HOME: "/home/u", CRED_STORE_DIR: "/srv/vault", CRED_CMD: "cred", CRED_GUARD_EXTRA_VARS: "WRAPPER_DIR" });
const GUARD = join(import.meta.dir, "..", "src", "guard.ts");

const DENY: string[] = [
  "pass show x", "pass x", "pass grep -e ''", "pass otp x", "pass git log -p", "pass ls foo", "pass -c foo", "pass edit foo",
  "gpg -d f", "gpg --decrypt f", "gpg -qd f", "gpg f.gpg", "gpg --export-secret-keys", "gpg --dec f", "gpg --export-secret-k",
  "gpg --command-fd 0 --list-keys", "gpg --options f --list-keys", "gpg < f.gpg", "gpg2 -d f", "gpgsm --decrypt f", "gpgtar --decrypt x",
  "bash -c 'pass show x'", 'sh -lc "pass x"', "echo $(pass show x)", "echo `pass show x`", 'eval "pass show x"',
  "sudo pass show x", "env A=1 pass show x", "echo x | xargs pass show", "timeout 5 pass show x",
  "script -qc 'pass show x' /dev/null", "bun cred.ts exec n -- pass show x", "find . -exec pass show {} \;",
  `python3 -c 'subprocess.run(["pass","show","x"])'`, "bash <<EOF\npass show x\nEOF", "cat <<'EOF' | bash\npass show x\nEOF",
  "echo 'pass show x' | sh", "$'\\x70ass' show x", "case $x in a) pass show y;; esac", "p=pass; $p show x",
  "/usr/bin/pass show x", "\\pass show x", "cat ~/.password-store/x.gpg", "git -C ~/.password-store log -p",
  "cp -r ~/.password-store /tmp/y", "ls $PASSWORD_STORE_DIR", "ls /srv/vault/x", "cat ~/.gnupg/private-keys-v1.d/*",
  "gpg-connect-agent 'PKDECRYPT' /bye", "CRED_MANIFEST=/tmp/m bun cred.ts exec x -- true", "PASSWORD_STORE_DIR=/x pass ls",
  "export CRED_STORE_DIR=/tmp/s", "bash -c 'pass show \"x",
  // from the cross-vendor audit
  "bash -o pipefail -c 'pass x'", "function f { pass x; }; f", "gopass show x", "gopass cat x", "passage show x", "gpg-sq -d f",
  "git -c core.pager='pass show x' log", "git config alias.x '!pass show x'", `uv run python -c 'subprocess.run(["pass","x"])'`,
  "tar cz ~/.gnupg | base64", "cp -r ~/.gnupg /tmp/g", "WRAPPER_DIR=/tmp/x bun cred.ts exec a -- true",
];
const ALLOW: string[] = [
  "pass", "pass ls", "pass find x", "pass --help", "gpg --list-keys", "gpg -k", "gpg --export ABC", "gpg --verify f.sig",
  "gpg-connect-agent 'keyinfo --list' /bye", "cat > notes.md <<EOF\npass show x\nEOF", 'git commit -m "tests pass"',
  "grep -i password config.ini", "echo pass", "docker-credential-pass list", "gh auth status", "bun cred.ts exec github -- true",
  "git status && bun test", "rg password src/ | head", "$EDITOR --password-file x", "case $x in a) echo hi;; esac # pass",
  "bash -c 'echo \"x", "ls -la", "",
  "gopass ls team", "git -c color.ui=auto log", "uv run pytest -k pass", "ls ~/.gnupg", "bunx some-tool --pass",
];

describe("decision table", () => {
  for (const c of DENY) test(`deny: ${JSON.stringify(c)}`, () => expect(inspectCommand(c, cfg)).not.toBeNull());
  for (const c of ALLOW) test(`allow: ${JSON.stringify(c)}`, () => expect(inspectCommand(c, cfg)).toBeNull());
});

describe("file tools", () => {
  test("Read of a private key is denied", () => expect(inspectTool("Read", { file_path: "/home/u/.gnupg/private-keys-v1.d/A.key" }, "/tmp", cfg)).not.toBeNull());
  test("Grep inside the store is denied", () => expect(inspectTool("Grep", { pattern: "x", path: "/srv/vault" }, "/tmp", cfg)).not.toBeNull());
  test("Glob under the store is denied", () => expect(inspectTool("Glob", { pattern: "/home/u/.password-store/**" }, "/tmp", cfg)).not.toBeNull());
  test("Grep for the word PASSWORD_STORE_DIR in code is allowed", () => expect(inspectTool("Grep", { pattern: "PASSWORD_STORE_DIR", path: "/repo" }, "/repo", cfg)).toBeNull());
  test("Read of an ordinary file is allowed", () => expect(inspectTool("Read", { file_path: "/repo/README.md" }, "/repo", cfg)).toBeNull());
  test("any tool with its working directory inside the store is denied", () => expect(inspectTool("Bash", { command: "ls" }, "/srv/vault/sub", cfg)).not.toBeNull());
  test("other tools are not inspected", () => expect(inspectTool("Write", { file_path: "/srv/vault/x" }, "/tmp", cfg)).toBeNull());
});

async function hook(stdin: string, env: Record<string, string> = {}) {
  const p = Bun.spawn([process.execPath, GUARD], { stdin: new TextEncoder().encode(stdin), stdout: "pipe", stderr: "pipe", env: { ...process.env, CRED_CMD: "cred", ...env } });
  const [out, code] = await Promise.all([new Response(p.stdout).text(), p.exited]);
  return { out, code };
}

describe("hook protocol", () => {
  test("a denial is PreToolUse JSON with a reason naming the broker", async () => {
    const r = await hook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "pass show x" }, cwd: "/tmp" }));
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out);
    expect(j.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(j.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(j.hookSpecificOutput.permissionDecisionReason).toContain("cred exec <name> --");
  });
  test("an allowed command prints nothing", async () => {
    const r = await hook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/tmp" }));
    expect([r.code, r.out]).toEqual([0, ""]);
  });
  test("another tool prints nothing", async () => {
    const r = await hook(JSON.stringify({ tool_name: "Edit", tool_input: { file_path: "/tmp/x" } }));
    expect([r.code, r.out]).toEqual([0, ""]);
  });
  test("garbage on stdin fails open", async () => {
    const r = await hook("not json {");
    expect([r.code, r.out]).toEqual([0, ""]);
  });
  test("a command with no trigger word is not parsed, even if it would not parse", () => {
    expect(inspectCommand("echo 'unclosed", cfg)).toBeNull();
  });
});

describe("the guard itself", () => {
  test("never runs pass or gpg", async () => {
    const src = await Bun.file(GUARD).text();
    // (RegExp's .exec() is fine; process-starting calls are not.)
    expect(src).not.toMatch(/\b(spawn|spawnSync|execSync|execFile)\s*\(|Bun\.spawn|Bun\.\$|node:child_process/);
  });
});
