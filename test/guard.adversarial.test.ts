import { describe, expect, test } from "bun:test";
import { defaultConfig, inspectCommand, inspectTool, runHook } from "../src/guard.ts";

const cfg = defaultConfig({ HOME: "/home/u", CRED_STORE_DIR: "/srv/vault" });

type DenyCase = [command: string, rule?: string];
type DenyRow = { command: string; rule: string | undefined };
type AllowCase = string;
type ToolCase = {
  name: string;
  tool: string;
  input: Record<string, unknown>;
  cwd?: string;
  rule?: string;
};
type HookCase = {
  name: string;
  input: Record<string, unknown>;
  rule: string;
};
type HookDenyOutput = {
  hookSpecificOutput: {
    hookEventName: string;
    permissionDecision: string;
    permissionDecisionReason: string;
  };
};

// Commands are data only: no shell, subprocess, store, or keyring is opened.
function denies(rows: DenyCase[]): void {
  const cases: DenyRow[] = rows.map(([command, rule]: DenyCase): DenyRow => ({ command, rule }));
  test.each(cases)("should deny $command", ({ command, rule }: DenyRow): void => {
    const verdict = inspectCommand(command, cfg);
    expect(verdict).not.toBeNull();
    expect(verdict).toMatchObject({ rule: rule ?? expect.any(String) });
  });
}

function allows(rows: AllowCase[]): void {
  test.each(rows)("should allow %s", (command: string): void => {
    expect(inspectCommand(command, cfg)).toBeNull();
  });
}

function expectHookDenial(output: string, rule: string): void {
  expect(output).not.toBe("");
  const parsed: HookDenyOutput = JSON.parse(output);
  const reason: string = parsed.hookSpecificOutput.permissionDecisionReason;
  expect(reason).toBeString();
  expect(reason.length).toBeGreaterThan(0);
  expect(reason).toContain(`(${rule})`);
  expect(parsed).toMatchObject({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: expect.any(String),
    },
  });
}

describe("pass basics", (): void => {
  denies([
    ["pass show x", "pass"],
    ["pass x", "pass"],
    ["pass ls x", "pass"],
    ["pass list x", "pass"],
    ["pass grep password", "pass"],
    ["pass grep", "pass"],
    ["pass edit x", "pass"],
    ["pass otp x", "pass"],
    ["pass git show", "pass"],
    ["pass -c x", "pass"],
    ["pass --clip x", "pass"],
    ["pass show --clip x", "pass"],
    ["pass insert x", "pass"],
    ["pass generate x 32", "pass"],
  ]);
  allows([
    "pass",
    "pass ls",
    "pass list",
    "pass find x",
    "pass search x",
    "pass help",
    "pass --help",
    "pass -h",
    "pass version",
    "pass --version",
  ]);
});

describe("shell-syntax evasions", (): void => {
  denies([
    ["'pass' show x"],
    ['"pass" show x'],
    ['p"ass" show x'],
    ['"pa""ss" show x'],
    ["'pa''ss' show x"],
    ["\\pass show x"],
    ["pa\\ss show x"],
    ["pass \\\n show x"],
    ["pa\\\nss show x"],
    ["true; pass show x"],
    ["true && pass show x"],
    ["false || pass show x"],
    ["true | pass show x"],
    ["true |& pass show x"],
    ["true & pass show x"],
    ["true\npass show x"],
    ["( pass show x )"],
    ["{ pass show x; }"],
    ["if true; then pass show x; fi"],
    ["while true; do pass show x; break; done"],
    ["for i in a; do pass show $i; done"],
    ["case x in x) pass show x;; esac"],
    ["$'pass' show x"],
    ["$'\\x70ass' show x"],
    ["command pass show x"],
    ["command -- pass show x"],
    ["builtin pass show x"],
    ["builtin eval 'pass show x'"],
    ["/usr/bin/pass show x"],
    ["nohup pass show x"],
    ["nice -n 5 pass show x"],
    ["stdbuf -oL pass show x"],
    ["setsid pass show x"],
    ["echo x | xargs -I{} pass show {}"],
    ["echo x | xargs pass show"],
    ["parallel pass show ::: x"],
    ["watch -n1 pass show x"],
    ["tmux new-session -d 'pass show x'"],
    ["ssh localhost pass show x"],
    ["script -c 'pass show x' /dev/null"],
    ["su -c 'pass show x' u"],
    ["flock /tmp/l -c 'pass show x'"],
    ["timeout 5 pass show x"],
    ["sudo -u u pass show x"],
    ["env A=1 pass show x"],
    ["find . -exec pass show x \\;"],
    ["find . -execdir pass show x \\;"],
    ["bun cred.ts exec a -- pass show x"],
    ["wrapper -- pass show x"],
    ["bash -c 'pass show x'"],
    ["sh -lc 'pass show x'"],
    ["bash -c 'sh -lc \"pass show x\"'"],
    ['eval "pass show x"'],
    ["echo $(pass show x)"],
    ["echo `pass show x`"],
    ["x=$(pass show x)"],
    ["cat <(pass show x)"],
    ["time pass show x"],
    ["! pass show x"],
    ["exec pass show x"],
  ]);
});

describe("interpreters", (): void => {
  denies([
    ['python3 -c \'import subprocess;subprocess.run(["pass","show","x"])\'', "interpreter"],
    ['node -e \'require("child_process").execSync("pass show x")\'', "interpreter"],
    ['perl -e \'system("pass show x")\'', "interpreter"],
    ["ruby -e '`pass show x`'", "interpreter"],
    ['awk \'BEGIN{system("pass show x")}\'', "interpreter"],
    ['bun -e \'Bun.spawn(["pass","show","x"])\'', "interpreter"],
    ['python3 -c "print(open(\'/home/u/.password-store/x.gpg\', \'rb\').read())"', "interpreter"],
    ['python3 <<EOF\nimport subprocess\nsubprocess.run(["pass","show","x"])\nEOF', "interpreter"],
    ["bash <<'EOF'\npass show x\nEOF"],
    ["bash <<-EOF\n\tpass show x\n\tEOF"],
    ["bash <<< 'pass show x'"],
    ["echo 'pass show x' | sh"],
    ["printf 'pass show x\\n' | bash"],
    ["cat <<EOF | bash\npass show x\nEOF"],
    ['echo \'import subprocess;subprocess.run(["pass","show","x"])\' | python3', "interpreter"],
  ]);
});

describe("gpg", (): void => {
  denies([
    ["gpg -d f.gpg", "gpg"],
    ["gpg --decrypt f", "gpg"],
    // --decrypt takes no value; the guard should still reject this spelling.
    ["gpg --decrypt=f.gpg", "gpg"],
    ["gpg --dec f", "gpg"],
    ["gpg --decr f", "gpg"],
    ["gpg -o out -d f", "gpg"],
    ["gpg --output out --decrypt f", "gpg"],
    ["gpg --batch --yes f.gpg", "gpg"],
    ["gpg f.gpg", "gpg"],
    ["gpg < f.gpg", "gpg"],
    ["cat f.gpg | gpg", "gpg"],
    ["gpg --use-agent -d f", "gpg"],
    ["gpg -qd f", "gpg"],
    ["gpg -dq f", "gpg"],
    ["gpg2 -d f.gpg", "gpg"],
    ["gpgsm --decrypt f", "gpg"],
    ["gpgtar --decrypt f", "gpg"],
    ["gpgtar -d f", "gpg"],
    ["gpg --export-secret-keys", "gpg"],
    ["gpg --export-secret-key", "gpg"],
    ["gpg --passphrase-fd 0", "gpg"],
    ["gpg --pinentry-mode loopback -d f", "gpg"],
    ["gpg --list-packets f", "gpg"],
    ["gpg --show-session-key f", "gpg"],
    ["gpg-connect-agent 'PKDECRYPT' /bye", "gpg"],
    ["gpg-connect-agent <<< PKDECRYPT", "gpg"],
    ["gpg-connect-agent <<EOF\nPKDECRYPT\n/bye\nEOF", "gpg"],
    ["gpg-connect-agent --run file", "gpg"],
    ["gpg --list-keys --decrypt f", "gpg"],
  ]);
  allows([
    "gpg --list-keys",
    "gpg -k",
    "gpg -K",
    "gpg --list-secret-keys",
    "gpg --fingerprint",
    "gpg --verify f.sig",
    "gpg --import k.asc",
    "gpg --export -a KEY",
    "gpg --encrypt -r me f",
    "gpg -e -r me f",
    "gpg --recv-keys ABC",
    "gpg --version",
    "gpg --card-status",
    "gpg -r dave -e f",
    "gpg-connect-agent reloadagent /bye",
    "gpgconf --kill gpg-agent",
  ]);
});

describe("store paths", (): void => {
  denies([
    ["cat ~/.password-store/x.gpg", "store-path"],
    ["cat $HOME/.password-store/x.gpg", "store-path"],
    ["cat ${HOME}/.password-store/x.gpg", "store-path"],
    ['cat "$HOME"/.password-store/x.gpg', "store-path"],
    ['cat "/home/u/.password-store/x.gpg"', "store-path"],
    ["ls ~/.pass*", "store-path"],
    ["ls ~/.password-st?re", "store-path"],
    ["cat /srv/vault/x.gpg", "store-path"],
    ["cp -r /srv/vault /tmp/v", "store-path"],
    ["tar czf b.tgz /srv/vault", "store-path"],
    ["cd ~/.password-store && git log -p", "store-path"],
    ["git -C ~/.password-store log -p", "store-path"],
    ["cd /srv/vault; git show", "store-path"],
    ["rsync -a ~/.password-store/ /tmp/x", "store-path"],
    ["ls ~/.gnupg/private-keys-v1.d", "store-path"],
    ["cat ~/.gnupg/secring.gpg", "store-path"],
    ["cat < ~/.password-store/x.gpg", "store-path"],
    ["grep -r x /srv/vault", "store-path"],
    ["cat /opt/another/.password-store/x.gpg", "store-path"],
    ["PASSWORD_STORE_DIR=/tmp/s pass ls", "reconfigure"],
    ["export PASSWORD_STORE_DIR=/tmp", "reconfigure"],
    ["CRED_STORE_DIR=/tmp bun cred.ts exec x -- true", "reconfigure"],
    ["env PASSWORD_STORE_DIR=/x pass ls", "reconfigure"],
  ]);
  // Only the broker's locations count as reconfiguring it. CRED_CMD changes nothing but the deny
  // message, and other CRED_* names (CRED_UNDER_TEST in this repo's own tests) are not the broker's.
  allows(["export CRED_CMD=x", "declare -x CRED_X=1", "CRED_X=1 true"]);
});

describe("tool calls (inspectTool)", (): void => {
  const denied: ToolCase[] = [
    { name: "Read /home/u/.password-store/x.gpg", tool: "Read", input: { file_path: "/home/u/.password-store/x.gpg" }, rule: "store-path" },
    { name: "Read /srv/vault/x.gpg", tool: "Read", input: { file_path: "/srv/vault/x.gpg" }, rule: "store-path" },
    { name: "Read ~/.password-store/x.gpg", tool: "Read", input: { file_path: "~/.password-store/x.gpg" }, rule: "store-path" },
    { name: "Read /home/u/.gnupg/private-keys-v1.d/ABC.key", tool: "Read", input: { file_path: "/home/u/.gnupg/private-keys-v1.d/ABC.key" }, rule: "store-path" },
    { name: "Grep path=/srv/vault", tool: "Grep", input: { pattern: "x", path: "/srv/vault" }, rule: "store-path" },
    { name: "Grep glob=**/.password-store/**", tool: "Grep", input: { pattern: "x", glob: "**/.password-store/**" }, rule: "store-path" },
    { name: "Glob pattern=/srv/vault/**/*.gpg", tool: "Glob", input: { pattern: "/srv/vault/**/*.gpg" }, rule: "store-path" },
    { name: "Glob pattern=**/*.gpg path=/home/u/.password-store", tool: "Glob", input: { pattern: "**/*.gpg", path: "/home/u/.password-store" }, rule: "store-path" },
    { name: "Bash ls cwd=/srv/vault/sub", tool: "Bash", input: { command: "ls" }, cwd: "/srv/vault/sub", rule: "store-cwd" },
    { name: "Read x.gpg cwd=/srv/vault", tool: "Read", input: { file_path: "x.gpg" }, cwd: "/srv/vault", rule: "store-cwd" },
  ];
  test.each(denied)("should deny $name", ({ tool, input, cwd, rule }: ToolCase): void => {
    expect(inspectTool(tool, input, cwd, cfg)).toMatchObject({ rule });
  });

  const allowed: ToolCase[] = [
    { name: "Grep pattern=password-store path=/home/u/project", tool: "Grep", input: { pattern: "password-store", path: "/home/u/project" } },
    { name: "Read /home/u/project/README.md", tool: "Read", input: { file_path: "/home/u/project/README.md" } },
    { name: "Edit /home/u/project/notes.md", tool: "Edit", input: { file_path: "/home/u/project/notes.md", old_string: "pass", new_string: "broker" } },
    { name: "Write /home/u/project/notes.md", tool: "Write", input: { file_path: "/home/u/project/notes.md", content: "pass show is blocked" } },
    { name: "UnknownTool command=pass show x", tool: "UnknownTool", input: { command: "pass show x" } },
    { name: "Glob pattern=**/*.ts path=/home/u/project", tool: "Glob", input: { pattern: "**/*.ts", path: "/home/u/project" } },
  ];
  test.each(allowed)("should allow $name", ({ tool, input, cwd }: ToolCase): void => {
    expect(inspectTool(tool, input, cwd, cfg)).toBeNull();
  });
});

describe("runHook protocol", (): void => {
  const denied: HookCase[] = [
    { name: "Bash pass show x", input: { tool_name: "Bash", tool_input: { command: "pass show x" } }, rule: "pass" },
    { name: "Bash gpg -d f.gpg", input: { tool_name: "Bash", tool_input: { command: "gpg -d f.gpg" } }, rule: "gpg" },
    { name: "Read /srv/vault/x.gpg", input: { tool_name: "Read", tool_input: { file_path: "/srv/vault/x.gpg" } }, rule: "store-path" },
    { name: "Bash ls cwd=/srv/vault/sub", input: { tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/srv/vault/sub" }, rule: "store-cwd" },
  ];
  test.each(denied)("should return a PreToolUse deny with its rule for $name", async ({ input, rule }: HookCase): Promise<void> => {
    expectHookDenial(await runHook(JSON.stringify(input), cfg), rule);
  });

  const garbage: string[] = ["not json", "", "null", "42", "[]"];
  test.each(garbage)("should return exactly empty output without throwing for garbage %j", async (stdin: string): Promise<void> => {
    await expect(runHook(stdin, cfg)).resolves.toBe("");
  });

  const allowed: [name: string, input: Record<string, unknown>][] = [
    ["Bash bun cred.ts exec x -- true", { tool_name: "Bash", tool_input: { command: "bun cred.ts exec x -- true" } }],
    ["Bash with missing tool_input", { tool_name: "Bash" }],
    ["WebFetch https://example.invalid", { tool_name: "WebFetch", tool_input: { url: "https://example.invalid" } }],
    ["Bash tool_input.command=42 (non-string)", { tool_name: "Bash", tool_input: { command: 42 } }],
    ["Read /home/u/project/README.md", { tool_name: "Read", tool_input: { file_path: "/home/u/project/README.md" } }],
  ];
  test.each(allowed)("should return exactly empty output without throwing for %s", async (_name: string, input: Record<string, unknown>): Promise<void> => {
    await expect(runHook(JSON.stringify(input), cfg)).resolves.toBe("");
  });
});

describe("false positives (MUST ALLOW)", (): void => {
  allows([
    'git commit -m "fix: pass the token through"',
    "git commit -m 'pass show is blocked now'",
    "grep -rn password src/",
    "grep password README.md",
    "rg passwd /etc",
    "docker-credential-pass list",
    "gh auth status",
    "gpg --list-keys",
    "bun cred.ts exec x -- true",
    "bun cred.ts list",
    "pass",
    "pass ls",
    "pass find aws",
    "bun test --pass-with-no-tests",
    "bun run passport-build",
    "echo bypass",
    "ls compass/",
    "cat passwd.example",
    "vim ~/notes/password-ideas.md",
    "ssh-keygen -t ed25519",
    "git log --grep=pass",
    "curl -u user:$TOKEN https://x",
    "export PASS_THRESHOLD=3",
    "ls ~/.gnupg",
    "gpg --list-secret-keys --keyid-format long",
    'echo "use pass show to read" > notes.txt',
    "cat README.md | grep pass",
    "make passthrough",
    "jq '.password' cfg.json",
    "kubectl get secret x -o yaml",
    "git diff -- src/guard.ts",
    "bun run src/cred.ts exec api -- curl https://x",
    "ls /srv/vault-backup",
    "cat /home/u/project/passwords.md",
  ]);
});

describe("out-of-scope obfuscation", (): void => {
  // Cheap to catch, so caught: an alias body, and what printf writes into a shell.
  denies([
    ["alias p='pass show'; p x"],
    ["printf '\\x70ass show x\\n' | sh"],
  ]);
  // Known limits (README "Limits"): building the name at run time, decoding a payload, or running a
  // script file. A tripwire for honest agents cannot see these; gpg-agent is the real boundary.
  for (const c of [
    "p=pa; ${p}ss show x",
    'p="pa"; q="ss"; "$p$q" show x',
    "echo cGFzcyBzaG93IHg= | base64 -d | sh",
    "printf 'pass show x\\n' > /tmp/read-secret.sh; bash /tmp/read-secret.sh",
  ]) test.todo(`known limit: ${c}`);
});

describe("expansion contexts the parser skips", (): void => {
  denies([
    ["cat > .env <<EOF\nTOKEN=$(pass show api)\nEOF"],
    ["cat > .env <<EOF\nTOKEN=`pass show api`\nEOF"],
    ['echo "${TOKEN:-$(pass show api)}"'],
    ["echo $(( $(pass show x | wc -c) ))"],
  ]);
  allows([
    "cat > notes.md <<'EOF'\nTOKEN=$(pass show api)\nEOF",
    "git commit -m \"$(cat <<'EOF'\nFix password handling; pass show no longer used\nEOF\n)\"",
  ]);
});

describe("wrappers and interpreters the dispatcher misses", (): void => {
  denies([
    ["/usr/bin/time -v pass show x"],
    ["time -p pass show x"],
    ["sudo -Hu alice pass show x"],
    ["sudo -iu alice pass show x"],
    ["coproc pass show x"],
    ["pkexec pass show x"],
    ["screen -dmS s pass show x"],
    ["fd -e gpg -x gpg -d"],
    ["tcsh -c 'pass show x'"],
    [`node -e 'console.log(require("child_process").execSync("pass github").toString())'`],
    ["perl -e 'print `pass github`'"],
    [`python3 -c 'import subprocess,sys; print(subprocess.check_output("pass " + sys.argv[1], shell=True))' api`],
  ]);
  allows(["command -v gpg", "type gpg", "gpg --help"]);
});

describe("custom store spelled relative or globbed", (): void => {
  denies([["cd /srv && cat vault/x.gpg"], ["cat /srv/vau*/x.gpg"]]);
  test("Read relative path resolved against cwd /srv into /srv/vault", (): void => {
    expect(inspectTool("Read", { file_path: "vault/x.gpg" }, "/srv", cfg)).not.toBeNull();
  });
  test("Glob vault/** under path /srv", (): void => {
    expect(inspectTool("Glob", { pattern: "vault/**/*.gpg", path: "/srv" }, "/home/u", cfg)).not.toBeNull();
  });
  test("~ expands to cfg HOME, not the process homedir(): cat ~/secrets/x.gpg", (): void => {
    const custom = defaultConfig({ HOME: "/home/u", PASSWORD_STORE_DIR: "/home/u/secrets" });
    expect(inspectCommand("cat ~/secrets/x.gpg", custom)).not.toBeNull();
  });
});
