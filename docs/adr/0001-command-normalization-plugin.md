# Canonicalize bash commands via plugin instead of enumerating path-form permission rules

## Status

accepted

## Context

opencode normalizes permission **patterns** and **commands** asymmetrically. As
observed in opencode v1.15.13 source, config patterns are expanded at load time
(`~/`, `~`, `$HOME/`, `$HOME` → absolute home path; `permission/index.ts:280-296`),
but bash commands are matched against their raw, pre-shell-expansion source text
(`tool/shell.ts:122-124, 403-405`). A tilde-form allow rule therefore can never
match a tilde-form command, and the only config-only workaround is an unsafe
leading-wildcard substring rule (for example, `*tool.sh*`) that over-permits
compound commands such as `bash -c "rm -rf ~ ; tool.sh"`.

## Decision

Normalize the command, don't enumerate the patterns. The plugin hooks
`tool.execute.before` for `tool === "bash"` and mutates `output.args.command` in
place before opencode matches it. The plugin rewrites command-node `argv0` values
to canonical absolute form so commands converge on the same absolute form config
patterns already expand to. Anchored-absolute allow rules then match without any
wildcard substring rules.

By default, only four home forms expand, and only when they appear as `argv0` at
the start of a command node: `~`, `~/...`, `$HOME`, and `$HOME/...` →
`$HOME/...`. `${HOME}` and `${HOME}/...` are opt-in via `expandBraceHome: true`.
The plugin never expands home forms in argument position.

Command nodes are split at argv0-start delimiters `&&`, `||`, `|`, `|&`, `;`, `&`,
and newlines, respecting quotes. The plugin returns the original command
unchanged on global uncertainty: unbalanced quotes, `<<` heredoc text, `$((`
arithmetic expansion, `$(` command substitution, backticks, `<(`, or `>(`. It
also returns the original command unchanged when any segment has a leading `(` or
`{`, a leading quote, a leading `WORD=` environment assignment, quotes inside
`argv0`, or `..` inside `argv0` while roots are configured.

Consumers may configure `roots` as a blast-radius limiter. When an expanded
`argv0` is not under any configured root, that segment is left unchanged. Roots
are normalized through the same home-expansion rules and rejected if the
normalized value is not absolute or contains `..`; malformed plugin options
disable the plugin.

## Considered options

- **Config codegen / regex authoring → many glob variants** (rejected): plugins
  cannot inject or modify permission rules at runtime (no registry API; the
  ruleset is static and compiled once), so this could only be a static
  config-generation step — and it still cannot match a raw tilde command without
  the unsafe leading-wildcard form.
- **Broad `bash` allow + plugin blocks dangerous commands** (rejected): fails open
  if the plugin fails to load.

## Consequences

- The plugin must be **execution-equivalent** (only ever rewrite to the path the
  shell would itself produce) and must preserve deny-side parity: any load
  failure, uncertainty, malformed option, relative log override, or out-of-root
  `argv0` leaves the original command unchanged for the normal configured
  permission rules to allow, deny, or ask. The plugin never makes a command more
  permissive than its raw form would be because opencode expands deny patterns
  the same way it expands allow patterns.
- The plugin writes an audit side effect independently of canonicalization: one
  NDJSON record per command node is appended to the default audit log. By
  default that log lives below the platform data-home fallback path under the
  historical `opencode/permission-audit-plugin` subfolder; debug messages use
  the same subfolder. Append failures are caught and logged to debug when
  possible, and debug-write failures are swallowed, so audit logging cannot
  change the canonicalized command returned to opencode.
- The plugin captures interactive permission decisions through opencode's
  interim generic `event` hook. It caches `permission.asked` by the composite
  `(properties.sessionID, properties.id)` key, joins
  `permission.replied` by `(properties.sessionID, properties.requestID)`, and
  writes a separate `decisions.log` record. Static allow and static deny paths do
  not emit permission events, so they are not represented in this log. The
  in-memory key uses a NUL delimiter because opencode session and request ids do
  not contain NUL.
- Decision capture normalizes `reply` before writing. JSON-serializable values
  are preserved verbatim; `undefined`, functions, symbols, and non-finite
  numbers are recorded as `null` in NDJSON; and values that fail JSON
  serialization are coerced to a string, falling back to
  `"[unserializable reply]"` if string coercion also fails.
- Decision capture assumes the runtime's `permission.asked.properties.tool.callID`
  equals the `callID` observed by `tool.execute.before` for the same bash tool
  invocation. Unit tests can verify the local join behavior but cannot prove this
  cross-source runtime equality; if the asked event omits `tool.callID`, the
  plugin records `callID: null` and emits a debug line to make the gap
  observable.
- Decision capture also assumes the runtime's `permission.replied.properties.sessionID`
  identifies the same session as the matching `permission.asked.properties.sessionID`.
  A reply without the matching session id is treated as an orphan and logged to
  debug rather than falling back to request-id-only correlation.
- A future opencode that wires the `permission.ask` hook (observed as declared
  but unwired in opencode v1.15.13; upstream #7006/#19453) would offer a cleaner
  mechanism for decision capture; the event-hook implementation should be
  revisited if that lands.
