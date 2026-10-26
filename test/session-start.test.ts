import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { build, defaultConfig, runHook } from "../src/session-start.ts";

const tmp = realpathSync(mkdtempSync(join(tmpdir(), "cred-ss-")));
const store = join(tmp, "store");
const cfgDir = join(tmp, "cfg");
mkdirSync(join(store, "svc"), { recursive: true });
mkdirSync(cfgDir, { recursive: true });
writeFileSync(join(store, "svc", "github.gpg"), "ciphertext");
const manifest = join(cfgDir, "manifest.yaml");
writeFileSync(manifest, [
  "github:", "  describes: GitHub token", "  pass_path: svc/github", "  env: GITHUB_TOKEN", "  risk: high",
  "later:", "  describes: Not stored yet", "  pass_path: svc/later", "  env: LATER_KEY",
  "_tool_native:", "  ssh:", "    describes: key auth", "    use: just run ssh",
  "_public:", "  deploy_key:", "    describes: public half", "    path: ~/.ssh/id.pub",
].join("\n"));
const cfg = { manifest, store, brokerCmd: "cred", note: join(cfgDir, "session-note.md") };
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("session-start", () => {
  test("hook output is SessionStart JSON", () => {
    const j = JSON.parse(runHook(cfg));
    expect(j.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(typeof j.hookSpecificOutput.additionalContext).toBe("string");
  });
  test("lists every brokered name with env var and stored flag", () => {
    const out = build(cfg);
    expect(out).toContain("| `github` | GitHub token _(high)_ | `$GITHUB_TOKEN` | yes |");
    expect(out).toContain("| `later` | Not stored yet | `$LATER_KEY` | **not yet** |");
    expect(out).toContain("| `ssh` | key auth | just run ssh |");
    expect(out).toContain("`deploy_key`");
  });
  test("advertises the configured broker command", () => {
    expect(build(cfg)).toContain("cred exec <name> -- <command...>");
    expect(build(cfg)).toContain("`! cred set <name>`");
  });
  test("never contains store contents", () => expect(build(cfg)).not.toContain("ciphertext"));
  test("names no machine-specific path", () => expect(build(cfg)).not.toContain(homedir()));
  test("appends the site note when present", () => {
    writeFileSync(cfg.note, "## Site policy\nAsk before using high-risk entries.\n");
    expect(build(cfg).trimEnd().endsWith("Ask before using high-risk entries.")).toBe(true);
    rmSync(cfg.note);
  });
  test("missing manifest: no output", () => expect(runHook({ ...cfg, manifest: join(tmp, "none.yaml") })).toBe(""));
  test("broken manifest: no output", () => {
    const bad = join(tmp, "bad.yaml");
    writeFileSync(bad, "a: [unclosed\n");
    expect(runHook({ ...cfg, manifest: bad })).toBe("");
  });
  test("defaults follow XDG and CRED_* overrides", () => {
    const d = defaultConfig({ HOME: "/h" });
    expect(d.manifest).toBe("/h/.config/cred-broker/manifest.yaml");
    expect(d.store).toBe("/h/.password-store");
    expect(d.note).toBe("/h/.config/cred-broker/session-note.md");
    const o = defaultConfig({ HOME: "/h", CRED_MANIFEST: "/m/x.yaml", CRED_STORE_DIR: "/s", CRED_CMD: "c" });
    expect([o.manifest, o.store, o.brokerCmd, o.note]).toEqual(["/m/x.yaml", "/s", "c", "/m/session-note.md"]);
  });
});
