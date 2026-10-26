#!/usr/bin/env bun
// session-start — Claude Code SessionStart hook.
//
// Tells every session WHAT credentials exist and HOW to use them, without ever telling it what
// they ARE. Names, descriptions and env-var mappings go into context; values stay encrypted in
// pass and only ever reach a child process started by the broker.
//
// Why it exists: a session that does not know the broker exists will ask the user to paste a
// credential into chat, and from there it reaches the transcript and the model provider.
// Discovery is the control: if the safe path is not obvious from the start, the unsafe path
// happens by default.
//
// Site policy: if `session-note.md` sits next to the manifest (or CRED_SESSION_NOTE names a
// file), its text is appended verbatim.
//
// Fails silent and open: a broken hook must never block a session.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import YAML from "yaml";

interface Entry { describes: string; pass_path: string; env: string; risk?: string; note?: string }
interface ToolNative { describes: string; use: string }

export interface SessionConfig {
  manifest: string;
  store: string;
  brokerCmd: string;
  note: string;
}

export function defaultConfig(env: Record<string, string | undefined> = process.env): SessionConfig {
  const home = env.HOME || homedir();
  const manifest = env.CRED_MANIFEST || join(env.XDG_CONFIG_HOME || join(home, ".config"), "cred-broker", "manifest.yaml");
  return {
    manifest,
    store: env.CRED_STORE_DIR || env.PASSWORD_STORE_DIR || join(home, ".password-store"),
    brokerCmd: env.CRED_CMD || `bun ${join(import.meta.dir, "cred.ts")}`,
    note: env.CRED_SESSION_NOTE || join(dirname(manifest), "session-note.md"),
  };
}

export function build(cfg: SessionConfig): string {
  if (!existsSync(cfg.manifest)) return "";
  let raw: Record<string, unknown>;
  try {
    raw = (YAML.parse(readFileSync(cfg.manifest, "utf8")) ?? {}) as Record<string, unknown>;
  } catch {
    return "";
  }
  if (typeof raw !== "object" || Array.isArray(raw)) return "";

  const brokered: Record<string, Entry> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k.startsWith("_")) continue;
    const e = v as Entry;
    if (e?.pass_path && e?.env) brokered[k] = e;
  }
  const native = (raw._tool_native ?? {}) as Record<string, ToolNative>;
  const pub = (raw._public ?? {}) as Record<string, Record<string, string>>;
  if (!Object.keys(brokered).length && !Object.keys(native).length) return "";

  const cmd = cfg.brokerCmd;
  const lines: string[] = [
    "## 🔐 Credentials — you can USE every one; you may not PRINT any",
    "",
    "Anything you see enters this transcript and is sent to the model provider; it may also be",
    "kept in logs or memory tools. A credential printed once is out of the user's control for good.",
    "So: use freely, never display.",
    "",
  ];

  if (Object.keys(native).length) {
    lines.push(
      "**Already works — just run the tool.** It holds its own secret and never shows you.",
      "",
      "| tool | what | how |",
      "|------|------|-----|",
    );
    for (const [n, e] of Object.entries(native)) lines.push(`| \`${n}\` | ${e.describes} | ${e.use} |`);
    lines.push("", "Their config files hold the secret — the tool reads them, you don't.", "");
  }

  if (Object.keys(brokered).length) {
    lines.push(
      "**Brokered — use `exec`, which injects the value into a child process:**",
      "",
      "| name | maps to | injects | stored |",
      "|------|---------|---------|--------|",
    );
    for (const [n, e] of Object.entries(brokered)) {
      const stored = existsSync(join(cfg.store, e.pass_path + ".gpg")) ? "yes" : "**not yet**";
      const risk = e.risk ? ` _(${e.risk})_` : "";
      lines.push(`| \`${n}\` | ${e.describes}${risk} | \`$${e.env}\` | ${stored} |`);
    }
    lines.push(
      "",
      "```bash",
      `${cmd} exec <name> -- <command...>`,
      "```",
      "The command's output is filtered: if it prints the value (or its base64, URL or JSON form) you",
      "see `[cred:<name>]` instead. That is the broker working, not a bug — do not try to get around it.",
      "Not stored yet? Do not work around it — ask the user to run",
      `\`! ${cmd} set <name>\` (it prompts on their tty; the value never passes through you).`,
      "",
    );
  }

  if (Object.keys(pub).length) {
    lines.push("**Public — not secrets. Read, quote, paste freely:**", "");
    for (const [n, e] of Object.entries(pub)) {
      lines.push(`- \`${n}\` — ${e.describes ?? ""}${e.path ? ` (\`${e.path}\`)` : ""}`);
    }
    lines.push("");
  }

  lines.push(
    "**The rule:** never ask the user to paste a credential into chat, and never run `pass show`,",
    "`gpg -d`, or read a tool's secret config. If you think you need a plaintext value, you need",
    "`exec` instead. Usernames, hostnames, IPs and public keys are not secrets — use them freely.",
    "",
  );

  if (existsSync(cfg.note)) {
    try { lines.push(readFileSync(cfg.note, "utf8").trimEnd(), ""); } catch { /* note is optional */ }
  }
  return lines.join("\n");
}

export function runHook(cfg: SessionConfig = defaultConfig()): string {
  try {
    const out = build(cfg);
    return out ? JSON.stringify({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: out } }) : "";
  } catch {
    return "";   // never block a session over the credential manifest
  }
}

if (import.meta.main) {
  const out = runHook();
  if (out) console.log(out);
  process.exitCode = 0;
}
