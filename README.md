# cred-broker

**Let your AI coding agent use your credentials without ever seeing them.**

Whatever an agent sees is captured. It enters the context window, is sent to the model provider,
is written to the session transcript, and is often copied on into memory or search tools. A
password that is printed once is in all of those places for good, and none of them is yours to
clean up.

cred-broker keeps the secret on your machine. Values stay encrypted in [`pass`](https://www.passwordstore.org/)
(GPG). The agent works with *names*: `cred exec github -- gh pr list`. The broker decrypts the value
into that one command's environment and streams back the command's output with the value filtered
out. The agent gets the result, and the secret stays off the model provider's servers, unless the
command itself transforms it or sends it somewhere (see [Threat model](#threat-model)).

It is ssh-agent's trick, generalised: `ssh host` is safe not because the key is encrypted, but
because the key never enters the conversation.

## How it works

Three small pieces, all local, all TypeScript on [Bun](https://bun.sh):

| Piece | What it does |
|---|---|
| `src/cred.ts`, the broker | `exec <name> -- <cmd>`: decrypt with `pass`, put the value in one env var of `<cmd>`, filter `<cmd>`'s stdout/stderr, write an audit record. There is deliberately no `get` or `show`. |
| `src/session-start.ts`, a SessionStart hook | Tells every agent session which credentials exist, what each is for, and how to use them. Never the values. An agent that knows about the broker doesn't ask you to paste secrets into chat. |
| `src/guard.ts`, a PreToolUse hook | Blocks the agent from going *around* the broker: `pass show`, `pass <name>`, `gpg -d`, `bash -c '…'` wrapping them, reads of the store or of gpg's private keys. It tells the agent to use `exec` instead. |

```
 agent: cred exec github -- gh pr list
          │
          ▼
 cred ── pass show agent/github ──► gpg-agent (your key, your passphrase)
   │
   ├─ spawns `gh pr list` with GITHUB_TOKEN=<value> in its env only
   ├─ filters its output: the value, base64 / base64url (any offset, so Basic auth),
   │  URL-encoded, JSON-escaped and shell-quoted forms all become [cred:github]
   └─ appends {who, what, when, exit code, how many redactions} to the audit log
          │
          ▼
 agent sees: the PR list, and never the token
```

## Threat model

Read this before trusting it.

**What it protects against.** An *honest* agent (the normal case) leaking a credential into its
transcript by accident:
- printing the value itself;
- `curl -v` showing an `Authorization` header;
- an error message echoing a URL with a key in it;
- `bash -x` tracing;
- you pasting a password into chat because the agent asked.

With cred-broker the agent has no reason to ask and no easy way to print. The output filter
catches the common encodings, and the guard catches the common ways round the broker.

**What it does not protect against.**
- **A deliberately malicious agent or process running as your user.** Anything with your uid can
  talk to gpg-agent's socket and decrypt, edit the broker or its manifest, or rewrite the audit
  log. **The guard is a tripwire, not a boundary.** It stops the obvious commands, and someone
  determined can always build `pass` at run time. The real boundaries are gpg-agent (a short cache
  TTL, pinentry confirmation) and running decryption as a different user. Separate-user decryption
  is the planned v2.
- **The value leaving through a side door.** The command you `exec` gets the value; whatever it
  sends over the network or writes to a file is not filtered. That is the point of giving it the
  value. Only stdout and stderr, which the agent reads, are filtered.
- **Transformed copies.** `| rev`, hex, gzip, or base64 wrapped across lines are not recognised.

The guarantee is narrower than "secrets are safe", and more useful: **nobody has to paste a
credential into an agent, and no session has a reason to print one.**

## Requirements

- Linux. This is what is tested; macOS is untested (gpg, `script` and `systemd-run` differ there,
  and reports are welcome).
- [Bun](https://bun.sh) 1.1 or later.
- GnuPG and `pass` (`sudo apt install gnupg pass`).
- Optional: a systemd user session, so unlock windows close on time even after logout.

## Install

```bash
git clone https://github.com/kcherry497/cred-broker ~/.local/share/cred-broker
cd ~/.local/share/cred-broker && bun install --frozen-lockfile
alias cred="bun ~/.local/share/cred-broker/src/cred.ts"     # add to your shell rc
cred doctor
```

`cred doctor` checks everything below and prints the exact command for anything missing.

## Quickstart

1. **A key and a store.** Skip this if you already use `pass`. A store just for agent credentials is
   recommended, so that unlocking it doesn't open everything else you keep in `pass`:

   ```bash
   gpg --quick-generate-key "Your Name <you@example.com>" default default never
   export CRED_STORE_DIR=~/.local/share/cred-broker-store      # add to your shell rc
   PASSWORD_STORE_DIR=$CRED_STORE_DIR pass init you@example.com
   ```

2. **A manifest.** Names and descriptions only, never values:

   ```bash
   mkdir -p ~/.config/cred-broker
   cp examples/manifest.example.yaml ~/.config/cred-broker/manifest.yaml   # then edit it
   ```

3. **Store a value, in your own terminal.** It prompts; the value never passes through the agent:

   ```bash
   cred set github
   ```

   Inside Claude Code, prefix it with `!` (`! cred set github`) so it runs on your tty.

4. **Use it:**

   ```bash
   cred exec github -- sh -c 'curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user | jq .login'
   cred exec github -- sh -c 'printf %s "$GITHUB_TOKEN"'      # prints [cred:github]
   ```

5. **Check:** `cred doctor`.

## Claude Code setup

Add both hooks to `~/.claude/settings.json` (full example: `examples/claude-settings.json`). Use
absolute paths:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "bun /home/you/.local/share/cred-broker/src/session-start.ts" }] }
    ],
    "PreToolUse": [
      { "matcher": "Bash|Read|Grep|Glob",
        "hooks": [{ "type": "command", "command": "bun /home/you/.local/share/cred-broker/src/guard.ts" }] }
    ]
  },
  "permissions": {
    "deny": [
      "Read(~/.password-store/**)", "Read(~/.gnupg/private-keys-v1.d/**)",
      "Edit(~/.gnupg/**)", "Edit(~/.config/cred-broker/**)", "Edit(~/.claude/settings.json)"
    ]
  }
}
```

The deny rules are a second layer: Claude Code enforces them itself, even in bypass mode.
- **The Read rules** back up the guard on the store and the private keys.
- **The Edit rules** stop the agent loosening gpg-agent's settings, adding entries to your
  manifest or session note, or unregistering the guard.

  Leave out the manifest rule if you want the agent to add manifest entries for you. Just review
  what it adds.

The guard covers what prefix rules can't, such as `pass github` (show is pass's default),
`bash -c 'pass show …'`, `$(pass …)` and heredocs. `cred doctor` runs the registered guard with a
probe and fails if it does not deny it. A hook that crashes is treated by Claude Code as "allow",
so that check matters.

If you set `CRED_STORE_DIR`, `CRED_MANIFEST` or `CRED_CMD` in your shell, make sure Claude Code
sees them too, for example in the `env` block of `settings.json`. `CRED_CMD` is the command the
hooks tell the agent to run, e.g. `"CRED_CMD": "bun /home/you/.local/share/cred-broker/src/cred.ts"`.

When the guard blocks something, the agent sees a message like:

> cred-broker guard (pass): blocked because \`pass show github\` can print a stored value. Use the
> broker, which hands the value to a command without showing it: \`cred exec <name> -- <command…>\`
> (names: \`cred list\`). If the user needs this command itself, they can run it in their own terminal.

Your own `!` commands and your terminal are not affected.

## Commands

| Command | What it does |
|---|---|
| `cred list` | What exists and what each maps to. No values. |
| `cred exec <name> -- <cmd…>` | Run `<cmd>` with the value in its env var; its output is filtered. Exit code is the command's (128+n if it is killed by signal n). |
| `cred status <name>` | Metadata for one entry. No value. |
| `cred set <name>` | Store a value. Interactive, on your own tty only; refuses a pipe. |
| `cred unlock [hours]` | Hold gpg-agent's passphrase cache for up to 12 h (default 12), so `exec` doesn't prompt. Interactive. |
| `cred lock` | Flush gpg-agent's cache now and restore your gpg-agent TTL settings. |
| `cred unlock-status` | Remaining unlock window (advisory). |
| `cred doctor` | Check gpg, pass, the store, the manifest, gpg-agent, the expiry timer and the Claude Code hooks. |
| `cred version` | Version, plus a hash of the source (compare an installed copy against the repo). |
| `cred relock <id>` | Run by the expiry timer: lock if unlock window `<id>` is still the current one. |

## Manifest format

```yaml
github:                         # the name the agent uses
  describes: GitHub token for my repos (contents read/write, PRs)   # shown to the agent
  pass_path: agent/github       # entry in the store, without .gpg
  env: GITHUB_TOKEN             # variable exec sets
  risk: medium                  # optional: low | medium | high
  format: line                  # optional: line (first line, the default) | full (multi-line: PEM, JSON)
  note: Expires every 90 days.  # optional, shown to the agent
```

`_tool_native:` and `_public:` sections are documentation only. They list tools that already keep
their own secret (ssh-agent, `gh`), and things that look secret but aren't (public keys), so the
agent stops looking for credentials it doesn't need. See `examples/manifest.example.yaml`.

A `session-note.md` next to the manifest is appended to the session briefing: put your own
policy there (`examples/session-note.md`).

**Neither file is a security boundary.** The manifest decides which store entries `exec` will
hand out. An agent that can edit it can broker any entry in the store, so keep only agent
credentials in that store. Every session reads the session note as your policy, so an edit there
persists across sessions. The `Edit` deny rules in [Claude Code setup](#claude-code-setup) close
both, and the guard does not cover file edits.

## Configuration

Everything has a default; set an env var to move it.

| Variable | Default | Meaning |
|---|---|---|
| `CRED_MANIFEST` | `$XDG_CONFIG_HOME/cred-broker/manifest.yaml` (`~/.config/…`) | The manifest. |
| `CRED_STORE_DIR` | `$PASSWORD_STORE_DIR`, else `~/.password-store` | The store `pass` reads for the broker. |
| `CRED_STATE_DIR` | `$XDG_STATE_HOME/cred-broker` (`~/.local/state/…`) | Unlock state. |
| `CRED_AUDIT_DIR` | `$CRED_STATE_DIR/audit` | Audit log. |
| `CRED_CMD` | `bun <repo>/src/cred.ts` | How the hooks tell the agent to run the broker. |
| `CRED_SESSION_ID` | Claude Code's session ID, else your username | Who an audit record names. |
| `CRED_SESSION_NOTE` | `session-note.md` next to the manifest | Extra text for the session briefing. |
| `CRED_RELOCK` | `systemd` | How unlock windows close: `systemd`, `detached` or `off`. |
| `CRED_GUARD_EXTRA_VARS` | (none) | Comma-separated extra variables the guard treats like the location variables, e.g. one a wrapper derives paths from. |

The guard denies an agent's attempt to set the location variables (`CRED_MANIFEST`,
`CRED_STORE_DIR`, `CRED_STATE_DIR`, `CRED_AUDIT_DIR`, `PASSWORD_STORE_*`, plus any in
`CRED_GUARD_EXTRA_VARS`). Pointing the broker at a manifest of its own would let an agent reach
entries you never listed. A wrapper script should set these itself rather than inherit them.

## Unlock windows

Without an unlock, gpg-agent prompts (pinentry) when its cache is cold. `cred unlock 4` asks for
your passphrase once and holds the cache for 4 hours.
- **How it works:** the broker writes a marked pair of TTL lines into `gpg-agent.conf` for the
  window, and saves your own TTL lines.
- **Closing:** `cred lock`, or the expiry timer, flushes the cache and puts your lines back.
- **The timer:** a systemd user timer, or a detached sleeper where systemd isn't available. A
  newer window is never cut short by an older window's timer.

While a window is open, anything running as your user can decrypt from that store. This is why a
dedicated store is recommended.

## Audit log

One JSON line per event in `$CRED_AUDIT_DIR/YYYY/MM/cred-YYYYMMDD.jsonl` (UTC). There is never a
value; copies of the value in argv are masked.

```json
{"timestamp":"2026-10-25T23:41:07.112Z","session":"a1b2…","event_type":"exec","key":"github","env":"GITHUB_TOKEN","command":"gh","risk":"medium","argv":["gh","pr","list"],"cwd":"/home/you/src/app","ppid":4242}
{"timestamp":"2026-10-25T23:41:07.903Z","session":"a1b2…","event_type":"exec_done","key":"github","exit":0,"signal":null,"duration_ms":791,"redactions":0}
```

Other events: `set`, `unlock`, `lock`, `relock`, `relock_skipped`, `exec_blocked`. The log is
written by your user, so it is a record of what happened, not proof against tampering.

## Limits

Known and documented, not bugs:

- **Output filter.**
  - Values under 4 bytes are not filtered at all (the broker warns).
  - base64 is caught at every offset only for values of 8+ bytes.
  - If a command prints the start of a value and then pauses for 150 ms, up to 3 bytes can show.
    Without that, prompts would hang. The rest of the value is still replaced.
- **Transformations and side channels.** `| rev`, hex, gzip, base64 across lines, and anything a
  command sends to the network or writes to a file are not filtered.
- **Env dumpers.** `exec` refuses `env`, `printenv`, `set`, `export` and `declare` as the command.
  This is a tripwire: `sh -c 'echo $X'` still works, by design, and the output filter is what
  catches it.
- **The terminal.** A command that opens `/dev/tty` and writes to it bypasses the filter. That
  only matters when `exec` runs in an interactive terminal.
- **Typing ahead.** `set` and `unlock` turn terminal echo off as soon as they start, so a value
  pasted before the prompt appears is not echoed. Anything typed in the first few milliseconds,
  before the broker is running, still is: wait for the prompt.
- **Guard.**
  - **Obfuscation it can't see:**
    - a name built at run time (`p=pa; ${p}ss show`);
    - a decoded payload (`base64 -d | sh`);
    - a script file written and then run;
    - an alias defined in one command and used in a later one.
  - **What it inspects:** only Claude Code's Bash, Read, Grep and Glob tools. Not MCP tools, not
    file edits (use the `Edit` deny rules above), and not tools it doesn't know.
  - **Tools it knows:** pass, gopass, passage, gpg/gpg2/gpgsm/gpgtar, and gpg-connect-agent.
    Other password-manager CLIs are not covered.
  - **Archives of your whole home directory:** it blocks copying or archiving `~/.gnupg`, but
    `tar cz ~` would still include the passphrase-protected keys and the store's ciphertext.
  - **What gets parsed:** a command is only parsed if it mentions something like `pass`, `gpg`,
    the store or an escape sequence. If such a command can't be parsed, it is denied as a
    precaution, so a command bash would also reject (e.g. one with an unbalanced quote) can be
    blocked this way.
  - **Your own repo work:** working on this repo's code, e.g. `grep '.password-store'` or inline
    test scripts that quote `"pass"`, trips it too. Put the code in a file or run it yourself.
- **Same user.** See the threat model. Separate-user decryption is planned.
- **Processes.** If the broker itself is SIGKILLed, the child keeps running. Two `unlock`s at once
  are not coordinated.
- **Other agents.** The broker and its output filter work with any agent that runs shell
  commands. The two hooks speak Claude Code's hook protocol. Adapters for other agents are welcome.

## Development

```bash
bun install
bun test              # broker e2e, redactor, guard (table + adversarial), session-start
```

The e2e suite creates a throwaway GPG key, store, manifest and audit directory under the system
temp dir. It refuses to run if any of them resolves elsewhere, and it checks that your real
`~/.gnupg/gpg-agent.conf` is byte-identical afterwards. `CRED_UNDER_TEST=/path/to/wrapper.ts`
runs the same suite through a wrapper script.

## License

MIT. See [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
