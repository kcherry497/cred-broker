# Security policy

## What this project promises

Read [the threat model](README.md#threat-model) first. In short: cred-broker keeps credentials out
of an **honest** agent's transcript. It is not a sandbox, and the guard hook is a tripwire, not a
boundary. Reports that show a way around the guard by deliberate obfuscation are welcome as
documentation improvements, but they are known limits, not vulnerabilities.

## What counts as a vulnerability

- A credential value, or one of the encodings the redactor claims to cover, reaching the
  agent's view of a command's stdout/stderr through `cred exec`.
- The broker writing a value to disk, to the audit log, or to argv.
- `set` or `unlock` accepting a secret from a non-interactive source.
- The guard allowing a command an honest agent would plausibly type that prints a stored value
  (for example a common `pass` or `gpg` form it misses).
- The tests touching the real password store, gpg-agent configuration or audit log.

## Reporting

Please use GitHub's private vulnerability reporting (the repository's **Security** tab →
**Report a vulnerability**). Do not open a public issue, and never include a real credential in
a report; a made-up value that reproduces the problem is enough.
