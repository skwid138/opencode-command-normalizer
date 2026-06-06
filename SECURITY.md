# Security

`@skwid138/opencode-command-normalizer` rewrites bash command text before
opencode's permission matcher sees it. Its scope is intentionally narrow:

- It handles bash tool executions only.
- It rewrites command-node `argv0` home forms only.
- It rewrites to the same absolute path the shell would use for home expansion.
- It never expands home forms in argument position.

## Bail philosophy

The plugin should prefer leaving a command unchanged over guessing. It bails out
on uncertain shell shapes such as heredocs, command substitution, arithmetic
expansion, process substitution, unbalanced quotes, grouped commands, leading
environment assignments, quoted `argv0`, and dot-dot `argv0` values when roots
are configured.

Leaving the command unchanged means opencode's normal permission rules still
decide whether to allow, deny, or ask.

## Fail-open intent

Malformed plugin options disable rewriting instead of blocking command execution.
Audit and debug logging failures are swallowed or logged best-effort, so logging
cannot change command execution. Relative audit/debug log overrides are ignored
and replaced with default absolute paths.

The plugin must not become a second policy engine. Policy remains in opencode's
configured permissions; this package only normalizes command spelling so anchored
rules can match consistently.
