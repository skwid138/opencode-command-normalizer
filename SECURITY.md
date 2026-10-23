# Security

`@skwid138/opencode-command-normalizer` rewrites bash command text before
opencode's permission matcher sees it. Its scope is intentionally narrow:

- It handles the V1 `bash` tool and the V2 `shell` tool only.
- It rewrites command-node `argv0` home forms only.
- It rewrites to the same absolute path the shell would use for home expansion,
  using the home directory the plugin resolves (the `homedir` option or the
  plugin process's home). On V2, whether that matches the home directory of the
  environment where the host runs shell commands has not been verified.
- It never expands home forms in argument position.
- On V2 it changes only `event.input.command`; it registers no permission,
  shell-environment, or other hooks.

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
cannot change command execution. On V2, any failure inside the hook is written
to the debug log and the command is left unchanged. Relative audit/debug log
overrides are ignored and replaced with default absolute paths.

The plugin must not become a second policy engine. Policy remains in opencode's
configured permissions; this package only normalizes command spelling so anchored
rules can match consistently.
