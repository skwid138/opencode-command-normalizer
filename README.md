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

## Configuration

Options:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `roots` | `string[]` | unset | Optional blast-radius limiter. Expanded `argv0` values outside configured roots are left unchanged. |
| `expandBraceHome` | `boolean` | `false` | Enables `${HOME}` and `${HOME}/...` expansion at command-node starts. |
| `homedir` | `string` | OS home directory | Test/advanced override for home expansion. |
| `auditLogPath` | `string` | data-home audit log | Absolute path override for the NDJSON audit log. Relative paths are ignored. |
| `debugLogPath` | `string` | data-home debug log | Absolute path override for debug messages. Relative paths are ignored. |

Default logs resolve lazily at plugin startup. If `XDG_DATA_HOME` is set to a
truthy absolute path, logs live below that directory; otherwise they live below
`$HOME/.local/share`. The subfolder intentionally keeps the historical name
`opencode/permission-audit-plugin` for continuity, even though the package is now
named command-normalizer.

`auditLogPath` and `debugLogPath` overrides must be absolute paths. Relative
override values are ignored and the defaults are used instead, preserving the
plugin's fail-open posture for malformed configuration.

## How it works

The plugin hooks `tool.execute.before` for bash tool executions and mutates
`output.args.command` before opencode permission matching. It expands only home
forms in `argv0` position at command-node starts:

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

## Development

```sh
npm install
npm test
npm run build
```

`npm run build` emits declarations and verifies the public TypeScript surface.

## Security

This package is a normalization aid, not a policy engine. It should only rewrite
to the path the shell would produce for home expansion, and it intentionally
bails out instead of guessing on ambiguous shell syntax. See [SECURITY.md](SECURITY.md)
for the command-rewrite scope and fail-open philosophy.

## License

MIT
