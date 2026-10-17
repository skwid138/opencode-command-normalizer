# opencode-command-normalizer

[![npm version](https://img.shields.io/npm/v/@skwid138/opencode-command-normalizer.svg)](https://www.npmjs.com/package/@skwid138/opencode-command-normalizer)
[![CI](https://github.com/skwid138/opencode-command-normalizer/actions/workflows/ci.yml/badge.svg)](https://github.com/skwid138/opencode-command-normalizer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Command normalization plugin for opencode permission matching.

## Why

opencode expands configured permission patterns such as `~/tool.sh` to absolute
home paths when it loads configuration, but bash commands are matched against the
raw command text. That means a command typed with a home-form `argv0` can miss an
otherwise anchored allow rule unless the config falls back to broad wildcard
patterns.

This plugin rewrites only command-node `argv0` home forms to the equivalent
absolute path before opencode's permission matcher sees the command. It is meant
to let anchored absolute permission rules work without unsafe leading wildcards.

## Install

```sh
npm install @skwid138/opencode-command-normalizer
```

Register it in opencode using the singular `plugin` config key in tuple form:

```jsonc
{
  "plugin": [
    [
      "@skwid138/opencode-command-normalizer",
      {
        "roots": ["~/workspace/tools"],
        "expandBraceHome": false
      }
    ]
  ]
}
```

Install the bare package name. The package also exposes `./server` for loaders
that resolve that subpath, but user installation should use
`@skwid138/opencode-command-normalizer`.

## Host support

One package serves both OpenCode plugin hosts from a single default export,
`{ id, server, setup }`, available from both `.` and `./server`:

| Host | Entry | Hook | Verification status |
| --- | --- | --- | --- |
| OpenCode V1 | `server` (existing plugin function) | `tool.execute.before` for tool `bash` | Unchanged V1 behavior; unit tested |
| OpenCode V2 | `setup(ctx)` | `ctx.tool.hook("execute.before")` for tool `shell` | Unit tested against a fake host and type-checked against `@opencode/plugin@2.0.28`; **not yet verified on a real V2 host** |

Upstream documents V1 object entrypoints as supported from OpenCode `1.18.29`.
Real-host loading, permission matching, and log output have not yet been
verified for this dual-host build on any V1 or V2 release; treat V2 support as
prepared, not proven.

The V2 adapter's host types are declared structurally, so neither the published
JavaScript nor the published declarations reference the V2 SDK
(`@opencode/*`). V1-only installs do not pull in the V2 dependency tree.

V2 configuration uses the `plugins` key with the same options:

```jsonc
{
  "plugins": [
    {
      "package": "@skwid138/opencode-command-normalizer",
      "options": { "roots": ["~/workspace/tools"], "expandBraceHome": false }
    }
  ]
}
```

## Configuration

Options:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `roots` | `string[]` | unset | Optional blast-radius limiter. Expanded `argv0` values outside configured roots are left unchanged. |
| `expandBraceHome` | `boolean` | `false` | Enables `${HOME}` and `${HOME}/...` expansion at command-node starts. |
| `homedir` | `string` | OS home directory | Test/advanced override for home expansion. |
| `auditLogPath` | `string` | data-home audit log | Absolute path override for the NDJSON audit log. Relative paths are ignored. |
| `debugLogPath` | `string` | data-home debug log | Absolute path override for debug messages. Relative paths are ignored. |
| `decisionsLogPath` | `string` | data-home decisions log | Absolute path override for the NDJSON permission decision log. Relative paths are ignored. |

Default logs resolve lazily at plugin startup. If `XDG_DATA_HOME` is set to a
truthy absolute path, logs live below that directory; otherwise they live below
`$HOME/.local/share`. The subfolder intentionally keeps the historical name
`opencode/permission-audit-plugin` for continuity, even though the package is now
named command-normalizer.

`auditLogPath`, `debugLogPath`, and `decisionsLogPath` overrides must be absolute
paths. Relative override values are ignored and the defaults are used instead,
preserving the plugin's fail-open posture for malformed configuration.

## How it works

On V1 the plugin hooks `tool.execute.before` for bash tool executions and
mutates `output.args.command` before opencode permission matching. On V2 it
registers `ctx.tool.hook("execute.before")`, acts only when `event.tool` is
`shell` and `event.input.command` is a string, and replaces only
`event.input.command`, and only when the normalized text differs. V2 audit
records take `callID` from `event.id` and `agent`/`sessionID` from the hook
event. On V2 any hook failure is written to the debug log and the command is
left as the host provided it. It expands only home forms in `argv0` position
at command-node starts:

- `~`
- `~/...`
- `$HOME`
- `$HOME/...`
- optionally `${HOME}` and `${HOME}/...` when `expandBraceHome: true`

Command nodes are split at shell separators such as `&&`, `||`, pipes,
semicolons, ampersands, and newlines while respecting quotes. The plugin returns
the original command unchanged for uncertain shell shapes such as heredocs,
command substitution, arithmetic expansion, process substitution, unbalanced
quotes, leading environment assignments, grouped commands, quoted `argv0`, and
dot-dot `argv0` values when roots are configured.

## Decision capture

The plugin also listens to opencode's generic `event` hook for interactive
permission prompts. It caches `permission.asked` events by the pair
`(event.properties.sessionID, event.properties.id)`, then joins the later
`permission.replied` event by `(event.properties.sessionID,
event.properties.requestID)`. Joined decisions are appended as NDJSON to a
separate `decisions.log`; the command-node `audit.log` schema is unchanged.

Decision records have this shape:

```ts
{
  ts: string;            // reply time
  sessionID: string;
  callID: string | null; // from permission.asked.properties.tool.callID
  requestID: string;
  permission: string;
  patterns: string[];
  always: string[];      // candidate patterns offered at ask time, independent of the chosen reply
  reply: unknown;        // recorded reply value; normally "once", "always", or "reject"
  askedTs: string;       // ask time
}
```

`reply` is normalized before writing so malformed runtime values cannot drop a
decision record. JSON-serializable values are preserved verbatim. `undefined`,
functions, symbols, and non-finite numbers are recorded as `null` in the NDJSON
output. Values that fail JSON serialization, such as `BigInt`, circular objects,
or throwing `toJSON` implementations, are coerced to a string; if string coercion
also fails, the plugin records `"[unserializable reply]"`.

Runtime event coverage:

| Permission path | Events emitted | Decision log entry |
| --- | --- | --- |
| Static allow | none | no |
| Static deny | none | no |
| Interactive ask | `permission.asked` + `permission.replied` | yes |

Use `callID` to join a decision record back to the command audit record emitted
for the same bash tool invocation. If opencode omits the asked event's tool
callID, the decision record uses `callID: null` and the plugin writes a debug
line so the gap is visible.

### Decision capture on V2

On V2 the plugin consumes `ctx.event.subscribe()` in the background (setup does
not wait on it) and writes the same `decisions.log` record shape. Field mapping:

| Decision field | V2 source |
| --- | --- |
| `requestID` | `permission.asked` `data.id`, joined to `permission.replied` `data.requestID` within the same `data.sessionID` |
| `permission` | `data.action` |
| `patterns` | `data.resources` |
| `always` | `data.save`, or `[]` when absent |
| `callID` | `data.source.id` when `data.source.type` is `tool`, otherwise `null` |
| `reply` | `data.reply` (`once`, `always`, or `reject`; other values are logged and recorded as described above) |
| `askedTs` / `ts` | times the plugin observed the ask / reply, not host event times |

Limits on V2:

- Capture is best effort and covers interactive asks only. It is not a stream
  of automatic allow/deny outcomes and does not record a final policy result.
  A reply is not necessarily a user click.
- Events published before the subscription is live can be missed; the plugin
  does not assume any subscription readiness guarantee from the host.
- Decision records have no `agent` field, as on V1.
- Stream failures are written to the debug log and stop decision capture for
  that plugin instance; command normalization keeps working.
- On unload the plugin aborts its subscription, disposes its hook, clears
  pending asks, and ignores later events. A write that has already started at
  unload may still complete.

## Development

```sh
npm install
npm test
npm run build
npm run test:pack
```

`npm run build` emits declarations and verifies the public TypeScript surface.

`npm test` runs through `test/run-isolated.mjs`, which gives the run a
throwaway `HOME`, XDG data/config/state/cache directories, and temp directory,
clears inherited `OPENCODE*` and npm config variables, and removes the
directory afterwards. Running `vitest` directly without the launcher is
refused. This keeps tests from writing to real user log directories; it is a
test-hygiene measure, not a security sandbox. `npm test` also type-checks
`src/**/*.test-d.ts` against the real V1 and V2 plugin type packages.

`npm run test:pack` (`node test/run-isolated.mjs node test/verify-pack.mjs`)
builds with `tsc`, constructs the package archive, extracts it into a clean
consumer with no dependencies installed, and checks both `.` and `./server`
imports. The archive is not made with `npm pack`: npm 10.9.2 was observed to
run the `prepare` (Husky) script even with `--ignore-scripts`.
`test/pack-artifact.mjs` instead stages exactly the expected regular files.
Those are `package.json` (byte-for-byte), `LICENSE`, `README.md`,
`SECURITY.md`, and a `.js` and `.d.ts` for each production module in `src/`.
It archives them with the system `tar` (clean environment, `COPYFILE_DISABLE=1`,
no inherited `TAR_OPTIONS`). Before anything is extracted, it validates the
archive within size caps: exact members, regular files only, exact bytes. It
refuses symlinked `src`/`dist` before building, and stale, missing, symlinked,
or special build outputs after. No lifecycle script runs.
This is constructed-archive consumer verification. It does not prove npm's
publish file selection. The archive is not byte-reproducible (entries are
sorted but mtimes are not normalized), and it is temporary: no release
candidate is frozen here.

`npm run test:pack:types` also installs the constructed archive into two throwaway
consumers (network access, a throwaway npm cache, `npm_config_userconfig=/dev/null`):
one with only the V1 type packages and one that adds `@opencode/plugin@2.0.28`.
The V2 consumer also installs `@types/json-schema@7.0.15`, because the
`@opencode/plugin@2.0.28` declarations (via `@ai-sdk/provider`) import
`json-schema` without declaring its types. That package is installed only in
the throwaway consumer, not as a dependency of this package.
It type-checks `.` and `./server` with `strict` and `skipLibCheck: false`, and
in the V2 consumer checks that the default export is assignable to the V2
`Plugin` type. It also includes checks that must fail to compile, proving the
host `Plugin`/`Context` types resolve to real types rather than `any`. Any
compiler error, non-zero exit, signal, or timeout fails the check.

`npm run test:real-host` is an opt-in real-host verification harness. It is
not part of `npm test` or CI. It is closed by default: until separately
approved staging and runtime gates are satisfied through a run manifest, it
starts nothing and exits non-zero. Its unit tests run as part of `npm test`.
They do not prove real-host isolation or dual-host support. See
[test/real-host/README.md](test/real-host/README.md).

## Security

This package is a normalization aid, not a policy engine. It should only rewrite
to the path the shell would produce for home expansion, and it intentionally
bails out instead of guessing on ambiguous shell syntax. See [SECURITY.md](SECURITY.md)
for the command-rewrite scope and fail-open philosophy.

## License

MIT
