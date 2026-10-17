# Real-host verification harness

Opt-in harness for proving the packed normalizer on real OpenCode hosts:
plugin loading, hook execution, the host's own permission checks consuming
the normalized command, and actual command execution. It does this without
touching the daily OpenCode config, credentials, database, or runtime.

Plan: `.project-plans/2026-10-13_isolated-real-host-verification.md`.

## Status

- **Gate 1 (approved, built):** the harness and its isolated unit tests.
  `npm test` runs the unit tests through `test/run-isolated.mjs`.
- **Gate 2 (exact downloads and staging):** V2 row only, under recorded user
  approvals (acquisition, single-member extraction, the offline archive copy
  and recipe, and a no-repack recovery). Staged and hash-recorded in the V2
  launch manifest: the V2 archive `cli-darwin-arm64-2.0.28.tgz`, its extracted
  `package/bin/opencode`, a hash-identical copy of Node v22.14.0, and the packed
  normalizer tarball `0.1.0`. The staged native V2 binary has not been
  executed. The staged Node was the target of the second pilot attempt's
  sandboxed provider launch (see Gate 3); whether it started is unknown. The
  V1 floor and daily rows are not acquired
  or staged, so Gate 2 is not complete for the matrix. During offline
  preparation `npm pack` ran the package `prepare` (Husky) script; the user
  accepted the resulting `.git/config` and `.husky/_` state and approved a
  no-repack recovery. Receipts live under
  `/private/var/folders/q1/zwn7qv6n4xd9wx2hvrz6cm5m0000gn/T/opencode/rh-v2-stage-pcVMsAFJ/`
  (for example `recovery-iHYJO9Js/receipt.txt`).
- **Gate 3 (sandbox safety pilot and runtime matrix):** not approved for any
  further run. Two separately approved V2 pilot attempts have run; both
  failed in preflight and both are consumed. Neither is retried here.
  - **First attempt (see Amendment A2):** prepare opened the registry
    tripwire listener, then preflight opened its IPv4 and IPv6 listeners and
    failed opening the Unix canary socket (`EADDRINUSE` on a 119-byte path),
    before any fake provider launch.
  - **Second attempt (see Amendment A3):** preflight opened and closed all
    three listeners and started the owned `sandbox-exec` provider launcher.
    The provider never reported readiness within the 30 s startup budget
    (`preflight fake provider did not report readiness`), with 0 bytes of
    provider stdout and stderr. The launcher's creation was recorded; that is
    not proof the Node entrypoint ran, and the cause is unknown.
  - Both attempts failed **before** any preflight control, sandboxed probe,
    version probe, OpenCode host, or scenario ran. Neither is sandbox proof of
    any kind, and no native OpenCode host or auth check has run.

`npm run test:real-host` is closed by default. It prints what it needs and
exits 2. It is not part of `npm test` or CI.

Passing unit tests do **not** mean isolation is ready. The sandbox profile is
a candidate; no preflight control has ever run on a real profile; `runtime.mjs`
has executed only as far as prepare, preflight listener setup, and one
provider launch that never became ready.

## Layout and reuse boundaries

Reusable controls (no normalizer knowledge; could be copied to another plugin
repo later, but nothing is extracted into a shared package or the bootstrap
repo):

| Module | Responsibility |
| --- | --- |
| `env.mjs` | Canonical fixture (HOME, four XDG dirs, TMPDIR, logs, project, bin, run, evidence) and a from-scratch environment allowlist. Explicit PATH (fixture bin + `/usr/bin:/bin:/usr/sbin:/sbin`); nothing inherited; no value may point into the real home. |
| `supervisor.mjs` | Explicit process-group ownership. TERM, bounded wait, KILL — owned groups only. Never uses `ps`/`pkill` snapshots. Refuses to remove a root while an owned group is alive. |
| `sandbox.mjs`, `probe.mjs` | Candidate deny-default `sandbox-exec` profile and the preflight evaluator and probe. |
| `artifacts.mjs`, `stage.mjs` | Exact matrix rows, zip/tar.gz listing, entry validation, single-member extraction, staged-file hash identity, runtime write tripwire, and the local-only Gate 2 helper. |
| `http.mjs` | Loopback-only HTTP client (numeric loopback with an explicit port), bodyless POST, deepObject query, bounded SSE parser. |
| `host-v1.mjs`, `host-v2.mjs`, `plugin-decl.mjs` | Host control boundaries: routes, reply semantics, event normalization, V2 plugin inventory, exact declaration remove/restore. |
| `fake-provider.mjs` | Self-contained OpenAI-compatible loopback endpoint that drives one scripted built-in tool call per request, with a finite call budget. |
| `executor.mjs`, `runner.mjs`, `gates.mjs`, `report.mjs`, `signals.mjs` | Scenario driving, ordering (stop owned processes → collect evidence → clean up), fail-closed runtime gates, and the sanitized report. |

Normalizer-specific: `scenarios.mjs` (matrix and evaluators), `contracts.mjs`
(the plugin id and the `permission asked cached` debug record),
`package-stage.mjs` (package name), and `runtime.mjs` (wiring).

## Provenance and contracts

`contracts.mjs` records every host contract and where it comes from.

**Verified against the pinned source commits** (read-only `gh api`, anomalyco/opencode):

- Pins: V1 floor `16747470`, compared at daily `53d1eabb`; V2 `026b106`.
- The files used were identical at both V1 pins, except `packages/core/src/npm.ts`, which differs only in non-Bun entrypoint resolution.

Verified values:

- **Server auth:** both hosts use the `OPENCODE_SERVER_PASSWORD` environment variable (V2 also accepts `OPENCODE_PASSWORD`). The username is `opencode`, the scheme is Basic, and a request without credentials gets a 401 with `www-authenticate: Basic realm="Secure Area"`. V2 picks a random password if none is set, so the harness always supplies one.
- **Launch argv:** `serve --hostname 127.0.0.1 --port <port>` for both hosts. The harness owns it; the manifest cannot set it.
- **V1 routes:**
  - `POST /session`
  - `POST /session/:id/prompt_async` → 204
  - `POST /permission/:id/reply {reply}` → boolean
  - `POST /instance/dispose`
  - `POST /session/:id/abort`
  - `GET /event`, whose envelope is `{id, type, properties}` and whose first event is `server.connected`
- **Tool arguments:** `{command}` for both hosts. The V1 tool id is `bash`; the V2 permission action is `shell`. For both hosts the last matching rule wins.
- **Permission outcomes on V1:** a rejection reads "The user rejected permission to use this specific tool call."; a deny starts with "The user has specified a rule which prevents you…"; an abort reads "Tool execution aborted".
- **Permission outcomes on V2:**
  - A rejection is `{type:"aborted", message:"The user declined this tool call"}`.
  - An interrupt is `{type:"aborted", message:"Tool execution interrupted"}`.
  - A static deny is `{type:"permission.rejected", message:"Permission denied: shell"}`. Traced at the V2 pin:
    1. `permission.ts` raises `BlockedError` (the message comes from the action when no hook supplies a reason).
    2. `shell.ts` `create` runs the callback directly, so the error passes through unchanged.
    3. The shell tool wraps it as `ToolFailure{error}`.
    4. `ToolFailure extends Tool.Error`, so `tool/runtime.ts` keeps it.
    5. `step.ts` calls `failTool(toSessionError(…))`.
    6. `to-session-error.ts` unwraps `.error`, and its `BlockedError` branch produces the shape above.
- **V2 `executed` flag:** in `session.tool.success/failed` this is `tool.providerExecuted`, so it is false for a locally executed tool (`publish-llm-event.ts` `toolExecution`). The harness reads it as `providerExecuted`. Local execution is proven only by the terminal event plus the execution record. A provider-executed terminal fails the scenario.
- **V2 config environment:** `OPENCODE_CONFIG` and `OPENCODE_DISABLE_PROJECT_CONFIG`.
- **V1 offline install fast path:**
  - Plugins resolve through `Npm.add("<spec>@latest")`. It skips installing when `$XDG_CACHE_HOME/opencode/packages/<spec>@latest/node_modules/<name>` already exists.
  - Each config directory runs `Npm.install(dir, add @opencode-ai/plugin)`. It skips installing when `node_modules` exists and `package-lock` `packages[""]` lists every declared name.
  - The harness preloads exactly these files, writes a fixture `$HOME/.npmrc` whose registry points at an owned tripwire listener, and checks the dependency regions after every step with no allow-list.

**V2 request and response schemas** come from `@opencode/protocol@2.0.28` and `@opencode/schema@2.0.28` in `node_modules`.

**Still unverified and review-gated** (`UNVERIFIED_CONTRACTS`; the runtime gate requires a review reference for each).

Handback for Gate 3: a review reference is an operator attestation recorded in the manifest. The gate checks only that one is present. It does not verify that a host-protocol review actually happened, so each item below must be reviewed for real before Gate 3:

- the V1 and V2 provider blocks (V2 is a template with exactly one `{providerBaseURL}` placeholder, which the harness fills with the port it allocated)
- the V1 permission map's insertion order
- the V2 cache layout and install recipe (dependency regions)
- whether npm reads `$HOME/.npmrc`, which the registry tripwire depends on
- the host version argv
- the sandbox Mach services and network semantics
- the archive recipe

**Other provenance notes:**

- **Prior art (reference only):** `ai-dev-bootstrap-mac/.project-plans/model-switch/{README.md, tests/real_opencode.bats, tests/helpers.bash, tests/fake_provider.py}`. Its allow-default profile was not copied.
- **The existing unit launcher** (`test/run-isolated.mjs`) only keeps unit tests tidy; it is not used as a boundary. It inherits PATH and signals only its direct child. The real-host environment is built from scratch, Node runs from an explicit staged path, and `bun` is never assumed.

## Ordering guarantees (runtime)

1. **Gates.** Before anything is created:
   - Roots are canonicalized: realpath of the nearest existing ancestor plus the remaining path components. They must be disjoint and outside the canonical real home.
   - Staged hashes are verified.
   - Provenance is linked: the binary's digest must equal the digest of the reviewed member inside the archive the plan pins, or of the approved installed file for the daily row.
   - Limit and member schemas are strict. Decompression is bounded while it happens.
2. **Prepare and preflight.** After prepare, a dependency-region baseline is recorded. Then the sandbox preflight runs:
   - Probe results are typed. Only a completed probe that reports EPERM or EACCES, after the control succeeded, counts as a denial.
   - No result, a timeout, or a nonzero exit is an infrastructure failure.
   - The provider positive control must return this run's identity token.
3. **Version probe.** A sandboxed version probe must report the row's exact version.
4. **Each launch:**
   - The provider proves its identity token.
   - The host starts sandboxed with a random, fixture-only password.
   - No control request is sent until the auth challenge passes (a 401 challenge, then 2xx with the password).
   - Every request and the SSE stream carry Basic auth and use `redirect: "error"`.
   - Opening the SSE stream has an independent deadline.
5. **Fail closed.** Any thrown or returned failure stops the run. That covers a scenario, lifecycle, version, preflight, tripwire, teardown, or cleanup failure, or an abort signal. No later scenario or row runs.
   - Inside the lifecycle, the first failed inventory, failed phase behavior, or audit count that doesn't match stops it before any further config mutation, rebuild, or prompt.
6. **Cleanup order:**
   - Stop owned groups, checking every `stopGroup` result; a survivor is a teardown failure.
   - Collect evidence, with the fixture password redacted.
   - Remove the root only through the retention gate: no owned group, spawned pid, or recorded fixture pid may be alive or of unknown liveness, and the record source must be intact. If the gate keeps the root, that is a cleanup failure that stops the matrix (see "Retention gate coverage boundary").
7. **Signals.** The first SIGINT or SIGTERM aborts the run and stops owned groups, then cleanup and the report still happen and the exit code is 130. A second signal exits immediately.
   - Stopping a group is idempotent and serialized per group, so the signal handler's stop and teardown's stop can overlap safely:
     - A concurrent stop shares the stop already in progress.
     - A group that was owned and has already finished returns its recorded result and is never signaled again.
     - Only a pgid that was never owned is refused.
   - A shutdown stop that fails is caught, never left as an unhandled rejection, recorded, and reported as a failure.
8. **Exec allowances.** The candidate profile allows process-exec only for exact paths from one contract list (`scenarios.mjs` `fixtureExecutables`, plus `env.mjs` `HOST_SHELL`):
   - the host binary
   - the staged Node
   - `/bin/bash`
   - the fixture `rh-probe` and `rh-sleep`
   - `/bin/sh`, `/bin/mv`, and `/bin/sleep`, which the fixture scripts call only by absolute path

   It never allows exec across the whole fixture.

## Scenarios and evidence rules

Matrix: ask-once pilot, plugin-absent baseline, `~` and `$HOME`, allow,
resource-specific deny, ask-reject, `roots: []` (separate), braces off and on
(with non-empty roots), lifecycle (active, removed, restored), cancel, and an
immediate first ask plus a later ask.

Evaluation is strict:

- **Completion:** prompt admission is not completion. A scenario completes
  only with a terminal tool result for the matching session and callID after
  submission, followed by idle or final evidence for that session. The SSE
  stream must connect before submission. A missing status is never success.
- **Execution evidence:** each execution writes one NUL-separated record:
  pid, HOME, physical cwd, argc, `$0`, and the full argv.
  - Every probe command carries a literal tail (`'~/lit' '$HOME/lit' '' 'a b'`),
    and argv must match exactly, including the empty argument.
  - Shell expansion of argv0 is not counted as normalizer evidence; audit text
    and permission patterns are.
- **Deny, reject, and cancel:** each must match its exact source-verified
  failure shape, with zero executions. Reject must also correlate to an
  explicit reject reply for the same call. Any other error fails the scenario,
  including a missing executable or bad input.
- **Audit records:** exactly one per actual callID. Lifecycle cardinality is
  1, 0, 1. Duplicate (idempotent) hooks fail.
- **Controlled replies:** wait for the plugin's matching
  `permission asked cached` debug record, then reply within a bounded
  deadline. The record is not a readiness signal.
- **No hidden retries:** the provider must issue exactly the scripted tool
  calls, stay within budget, and see the built-in tool advertised.
- **Report:** `complete` only when every row and scenario actually ran and
  passed. Otherwise it is `incomplete` or `failed`. Results are limited to the
  exact hashed binaries and this machine.

## Amendment A1 corrections (offline; source-verified, not native proof)

- **Exact V2 plugin spec.**
  - V2 declares, caches, and inventories one spec: `<name>@<exact version>`, read from the hash-verified packed `package.json`. A bare name would make the pinned V2 supervisor run an update check through pacote; an exact version makes `Npm.check` return false.
  - The gate requires the V2 row's `cache.specDir` to equal that spec.
  - Prepare re-derives the spec from the re-hashed tarball and refuses before staging or launch if the version is not exact (no ranges or tags), the bytes changed, or the spec differs.
  - V1 keeps the source-verified bare name and its `<name>@latest` cache path.
- **Strict version probe.** Whole stdout must equal `<version>` (V1) or `opencode v<version>` (V2; pinned Effect CLI 4.0.1), with at most one final newline. There is no trimming, first-line, or substring matching, so extra output fails. A nonzero exit, an error, or a timeout fails.
- **Immutable dependency baselines.**
  - Prepare records a baseline over these exact dependency regions (relative to the fixture root):
    - **V1:** `xdg/config/opencode/{node_modules, package.json, package-lock.json, .gitignore}` and `xdg/cache/opencode/packages`.
    - **V2:** the reviewed `dependencyRegions` under `xdg/`, plus the staged package directory.
    - **Both:** `home/.npm` and `home/.npmrc`. The existing registry tripwire setting is preserved, and no environment variables are added.
  - The baseline is written to `evidence/dependency-baseline.json` and pinned by an in-memory digest. It is never advanced.
  - Each per-step tripwire, and a final integrity check, compare against it. The final check runs after owned processes stop and before the fixture is deleted, on the normal, failure, and deadline paths. It also re-checks staged package content against the tarball.
  - A change, missing or corrupt baseline evidence, or any registry connection fails the row and keeps the root. Zero registry connections alone is never proof of no install.
  - An explicit skip happens only when prepare never made a baseline.
  - The database, logs, state, and host log directories are allowed runtime writes.
- **Inspection caps.**
  - `stage.mjs inspect` requires reviewed `--limits` for both archive kinds. Before any success output it enforces the actual entry count, the per-file size, and the summed size of the listing.
  - Bounded inflate and the strict limit schema are unchanged. The exact member allowlist is a separate, later review.
  - Proposed future V2 caps: 16 entries, 201326592 bytes per file, 201326592 bytes total. These give a raw tar cap of 201345024.
- **Pilot work deadline.**
  - `--execute --pilot` has an independent 15-minute work budget that starts before fixture prepare. It does not apply to the matrix.
  - On expiry, a run-wide abort signal stops owned process groups at once (before evidence). The runtime refuses every later spawn: each spawn boundary checks the signal, and it is rechecked after deferred awaits return. The in-flight step is awaited, never abandoned by a timer race.
  - Cleanup, final integrity, evidence, and a non-passing report then complete through the normal pipeline, using the existing bounded local stop waits. There is no hard wall-clock OS guarantee.
  - Group ownership is unchanged: there is no scan-derived kill and no all-descendant claim.

## Amendment A2 corrections (offline; not native proof)

- **Why.** The failed V2 pilot's actual canary socket path was 119 bytes
  (`<canaryRoot>/rh-canary-XXXXXX/forbidden.sock` under a long canary root).
  Darwin's `sun_path` holds 104 bytes including the terminating NUL. The
  observed `EADDRINUSE` was not reproduced, so the long path is not claimed as
  its cause. Separately, preflight acquired all three listeners before its
  protected region, so a Unix listener failure leaked the IPv4 and IPv6
  listeners until the CLI exited.
- **Socket pathname guard** (`socket-path.mjs`).
  - One set of constants drives both construction and the forecast: prefix
    `rh-canary-`, a six-character `mkdtemp` suffix, and the file name
    `forbidden.sock`.
  - A pathname is rejected when it contains NUL or exceeds 103 UTF-8 bytes
    (`Buffer.byteLength`). This is a Darwin harness limit, not a portable Unix
    claim.
  - **Gate forecast:** `--check` forecasts the socket path from the
    *canonical* `canaryRoot` (a short symlink alias of a long directory is
    still rejected). The forecast is not the sole proof.
  - **Runtime backstop:** preflight checks the actual path before its first
    listener (the registry tripwire listener is earlier and separate). Canary
    creation stays in prepare; ownership is not restructured.
  - **Test seams:** canary directory operations (create, `canary-read`,
    removal) go through `io.canaryFs` (production default: `node:fs/promises`
    `mkdtemp`, `writeFile`, `rm`), and the gate accepts an optional
    `canonicalize` (default `canonicalPath`). Unit tests use a short synthetic
    `/fixture/c` root backed inside the launcher-isolated root, with the
    103-byte guard still enabled.
- **Listener ownership and cleanup** (`listener-ownership.mjs`).
  - Preflight acquires its IPv4, IPv6, and Unix listeners one at a time inside
    the protected region, and registers each with its fixture the moment it
    exists.
  - The physical adapter's `close()` resolves only on the `server.close`
    callback; the return of `server.close()` is not confirmation.
  - Each listener has one close attempt. Repeated and concurrent callers share
    it and see the same outcome. A listener is closed only when the callback
    confirms it; a failure or timeout is sticky and never later converted to
    success.
  - A separate `listenerCloseMs` deadline (1 s, injectable) bounds the wait.
    It is independent of the work signal and the disarmed pilot work timer. A
    timeout leaves the listener unconfirmed, and a late rejection is observed,
    never unhandled. A bounded wait cannot prove the OS closed the socket.
  - Cleanup attempts every listener close and the provider stop even if one
    fails. The primary error is rethrown unchanged; secondary failures are
    recorded and appear in collected evidence (`evidence/listeners`,
    `evidence/cleanup-problems`). A close failure on an otherwise passing
    preflight is a teardown failure, never success.
  - The registry tripwire listener follows the same contract in the prepare
    failure path and in root removal (close-once and cancellation behavior are
    unchanged).
  - **Retention:** any listener not confirmed closed keeps the fixture root;
    root removal refuses to delete it, which the runner reports as a cleanup
    failure. There is no new kill authority and no stop redesign.
- **Short canonical candidate (documentation only).**
  `/private/var/folders/q1/zwn7qv6n4xd9wx2hvrz6cm5m0000gn/T/opencode/c` gives a
  99-byte forecast (`…/c/rh-canary-XXXXXX/forbidden.sock`). When A2 was
  written it was verified absent and had not been created. Using it needs a later, separately approved
  step: check existence read-only, do not `mkdir` it from this harness, and do
  not edit the retained failed launch manifest. Nothing here is a new manifest
  or a Gate 3 runtime approval; the consumed pilot attempt stays consumed.
  (Later, under the separately approved second pilot attempt, `c` was created
  empty with mode 0700; it is preserved and this harness never creates it.)

## Amendment A3 provider-startup diagnostics (offline; not native proof)

These changes are implemented and unit-tested offline only (socket-free,
injected I/O, no subprocess). They have not run against the staged Node, the
OS sandbox, or a native host, and they do not explain the second attempt's
failure; its cause remains unknown. Sandbox policy, launch argv, and the
provider environment are unchanged.

- **Shared provider startup wait** (`provider-startup.mjs`), used by preflight
  and by every host launch. Outcomes: `ready`, `exited-before-ready`,
  `startup-timeout`, `work-aborted`.
  - The existing `startupMs` (30 s) and `pollMs` are unchanged.
  - Any exit of the owned launcher before readiness fails at once (code 0, a
    nonzero code, or a signal), before any identity check, probe, or host
    launch. The owned group is still stopped: a leader exit does not mean the
    group is gone.
  - Precedence at each decision, including after every awaited readiness
    read: an observed work abort, then an observed exit, then readiness. This
    cannot remove races with the OS exit notification.
  - Every path disposes of its poll timer and abort listener; nothing polls
    after the wait settles, and a late exit is absorbed.
  - The ready path keeps the existing identity check and positive controls.
- **Bounded provider-only evidence** (`provider-evidence.mjs`), collected as
  structured data under `evidence/provider-launches` (never a JSON string):
  - captured BEFORE spawn: the label, the effective argv (at most 16
    elements), cwd, and the nine-key minimal env (`HOME`, `PATH`, `TMPDIR`,
    `LANG`, `SHELL`, four XDG keys); each string at most 4096 UTF-8 bytes;
  - the actual generated profile: a SHA-256 of the RAW bytes (read with a
    bounded read, at most 65536 bytes) and path-redacted text labelled as not
    replayable. The digest is of the raw bytes, not of the redacted text;
  - at most 32 launch records per fixture;
  - after spawn: the direct launcher's pid/pgid and its `exit` event (code or
    signal; not proof that Node ran), the startup outcome, and the raw stop
    result (`pgid`, `termSent`, `killSent`, `aliveAfter`, `unsafe`,
    `alreadyGone`), recorded before the termination check;
  - errors are a bounded name/code only, never a message.
  - Oversized or invalid evidence is an explicit capture failure before
    launch (recorded under `captureFailures`), never a silent truncation.
  - Excluded: provider config contents, identity tokens and identity
    response bodies, ledger contents, host auth headers, and passwords.
- **Evidence never owns cleanup.** Post-spawn recording is in memory and
  cannot throw; a recording failure cannot lose the owned handle, skip a stop
  or listener close, or replace the primary error. A rejected provider stop
  is reported by name/code. Retention rules are unchanged.
- **Report privacy.** Each provider identity token is registered as a
  redaction secret, so it is removed from collected evidence and the final
  report (it can appear in the preflight positive-control body).

## Future commands (each gate needs its own user approval; none is proposed here)

**Gate 2 — SUPERSEDED HISTORICAL SKETCH. NOT THE NEXT RECIPE. DO NOT RUN.**

> Amendment A1 is authoritative. After A1, the next separately approved step
> was the V2-only acquisition and inspection below ("Approved-separately path
> after Amendment A1"); it has since run (see Status). The block that follows
> is the original pre-A1 combined sketch, kept only as history.
>
> It conflicts with A1 in four ways:
> - it downloads V1 and V2 together
> - the V2 download has no size cap
> - it is not `-q` / `env -i` / `.part` / `--remove-on-error`
> - it chains extraction, copying, and packing
>
> None of it is approved or proposed.

```sh
# SUPERSEDED (pre-A1 history). Not a recipe. Do not run.
uname -m                                                            # expect arm64
/usr/bin/file /opt/homebrew/Cellar/opencode/1.18.35/bin/opencode    # metadata only, never executed; stop if it is a wrapper or symlink
curl --fail --location --proto '=https' --tlsv1.2 --max-time 300 --max-filesize 46205298 \
  -o "$STAGE/downloads/opencode-darwin-arm64-1.18.29.zip" \
  https://github.com/anomalyco/opencode/releases/download/v1.18.29/opencode-darwin-arm64.zip
curl --fail --location --proto '=https' --tlsv1.2 --max-time 300 \
  -o "$STAGE/downloads/cli-darwin-arm64-2.0.28.tgz" \
  https://registry.npmjs.org/@opencode/cli-darwin-arm64/-/cli-darwin-arm64-2.0.28.tgz
node test/real-host/stage.mjs inspect --kind zip --archive "$STAGE/downloads/opencode-darwin-arm64-1.18.29.zip" \
  --expect-sha256 fe764f7f360c584a83e18dd5f23fb1a6b2725f5ee8854b0252fe558f7798e946 --limits '<reviewed limits>'   # size must be 46205298
node test/real-host/stage.mjs inspect --kind tgz --archive "$STAGE/downloads/cli-darwin-arm64-2.0.28.tgz" \
  --expect-integrity sha512-HYFeBK8drYVq9b9DlQ51pBLCaL+GNyih1ysTQfmekW7YhAJngPYDM7xMgCINXopRVMGTw7EmbJPrMm+9V0G7Yg== \
  --limits '<reviewed limits>'   # required for every inspect: bounds decompression and caps the actual listing
# After the recipe review fixes members and limits from the inspect output:
node test/real-host/stage.mjs extract --kind zip|tgz --archive <archive> --member <reviewed member> \
  --dest "$STAGE/<row>/opencode" --limits '<reviewed>' --members '<reviewed>'
# Daily artifact copy, staged Node, and packed tarball, each followed by stage.mjs hash:
cp /opt/homebrew/Cellar/opencode/1.18.35/bin/opencode "$STAGE/v1-daily/opencode"
cp <explicit node executable> "$STAGE/node/node"
npm run build && npm pack --ignore-scripts --pack-destination "$STAGE/package"
node test/real-host/stage.mjs hash --file <each staged file>
```

(End of the superseded historical sketch.)

Gate 2 open items:

- The archive members and limits stay `null` in `artifacts.mjs` by design;
  reviewed values come from the run manifest. The V2 row's reviewed members
  and limits are recorded in its launch manifest; the V1 rows remain open.

**Approved-separately path after Amendment A1 (historical; it has since run):
V2-only acquisition, then inspection only.** A V2-only acquisition and
inspection along these lines ran under its own approval. The retained
acquisition logs
(`/private/var/folders/q1/zwn7qv6n4xd9wx2hvrz6cm5m0000gn/T/opencode/rh-v2-acquire-u5IvV9Sh/logs/`)
record results and hashes; exact acquisition argv/environment were not
retained, so invocation safeguards remain reported rather than independently
evidenced. This block is kept as the proposed recipe, not as proof of how the
acquisition was invoked. Do not rerun it.

```sh
part="$(mktemp "$STAGE/downloads/cli-darwin-arm64-2.0.28.tgz.XXXXXX")" && mv "$part" "$part.part" && part="$part.part"
env -i PATH=/usr/bin:/bin /usr/bin/curl -q --fail --location --proto '=https' --proto-redir '=https' --max-redirs 5 \
  --max-filesize 201326592 --max-time 300 --retry 0 --remove-on-error -o "$part" \
  https://registry.npmjs.org/@opencode/cli-darwin-arm64/-/cli-darwin-arm64-2.0.28.tgz
# Only after curl exits 0:
node test/real-host/stage.mjs inspect --kind tgz --archive "$part" \
  --expect-integrity sha512-HYFeBK8drYVq9b9DlQ51pBLCaL+GNyih1ysTQfmekW7YhAJngPYDM7xMgCINXopRVMGTw7EmbJPrMm+9V0G7Yg== \
  --limits '{"maxEntries":16,"maxFileBytes":201326592,"maxExpandedBytes":201326592}'
```

How to run it:

- **Download limits:**
  - Use the exact URL and SRI from the existing pin.
  - Cap the download at 192 MiB and 300 seconds, with no automatic retry.
  - Use curl ≥ 8.4 (the local metadata review saw 8.7.1).
  - Put `-q` first so no curlrc is read, and run under `env -i`.
  - Use HTTPS only, with at most 5 redirects.
  - Download to a unique `.part` file with `--remove-on-error`.
- **Inspection:** inspect only after a successful transfer. A verified
  integrity plus a numerically bounded listing is **not** member or extraction
  approval; STOP for the actual member review.
- **Later staging:** stage one V2 row only, then run `--execute --pilot`.
  - It runs controls, then the version check, then ask-once.
  - No automatic matrix runs, and there is no additional controls-only CLI.
- **Sandbox, unchanged:** the profile stays a CANDIDATE.
  - Owned loopback ports only (`localhost:<port>` IP rules).
  - Broad system read subpaths as the actual read policy.
  - Mach services `[]`.
  - There is no proof of TCP-only, IPv4-only, or exhaustive coverage.

**V2 provider values (source-verified manifest values, Amendment A1):**

```json
{
  "model": "fake/fake-model",
  "providers": {
    "fake": {
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": { "baseURL": "{providerBaseURL}", "provider": "fake", "apiKey": "fixture-placeholder-not-a-credential" },
      "models": { "fake-model": { "capabilities": { "tools": true, "input": ["text"], "output": ["text"] } } }
    }
  }
}
```

These values are source-verified only, not native proof. For the one V2
pilot, the `v2.providerConfig` review reference and the Gate 2/Gate 3
approvals were recorded in the V2 launch manifest from the user's approvals;
none is fabricated here. Any further step still needs its own recorded
approval.

**Gate 3 — sandbox safety pilot, then the matrix.**

```sh
npm run test:real-host -- --manifest "$STAGE/manifest.json" --check            # verifies gates and hashes; starts nothing
npm run test:real-host -- --manifest "$STAGE/manifest.json" --execute --pilot  # one row: controls, version, ask-once (15-minute work deadline)
npm run test:real-host -- --manifest "$STAGE/manifest.json" --execute          # full matrix, sequential
```

The manifest carries:

- `approvals.gate2` and `approvals.gate3`
- `platform`
- `runRoot`, `canaryRoot`, and `stagingRoot`, which are canonicalized, must be
  disjoint, and must be outside the real home; the canonical `canaryRoot` must
  also forecast a canary socket path of at most 103 UTF-8 bytes (Amendment A2)
- `reportPath`
- `node` and `tarball`: the staged path, sha256, and the Node version
- `rows[]`, each with:
  - `id`
  - `binary`: the staged path and sha256
  - `provenance`: either `{ archive: { path, sha256 | integrity }, member, limits, members }`
    (`stage.mjs extract` prints this) or, for the daily row,
    `{ source: { path, sha256 } }`
  - `cache`: for V1 this must be the source-verified
    `{XDG_CACHE_HOME}/opencode` + `<package>@latest`; for V2 the `specDir`
    must be the exact packed spec `<package>@<exact version>`
- `sandbox.machServices`
- `reviewedContracts`: a `review` reference for every unverified key, plus the
  `hosts.versionArgv` value
- the `v2` reviewed values: a `providers` template with one
  `{providerBaseURL}`, `model`, and `dependencyRegions`
- optionally, allowlisted `hostEnv` keys (never the password or
  `OPENCODE_CONFIG`) and `limits.providerCallBudget`

`launchArgv` is harness-owned and is rejected if present.

## Costs, timeouts, and caps

Plan estimates, which are not guarantees and exclude implementation time:

| Item | Estimate |
| --- | --- |
| Acquisition | 1–5 min |
| Pilot | 5–15 min |
| Matrix (sequential) | 2–8 min |
| Disk | 0.5–1.5 GB |
| RAM per host | 0.3–1 GB |

Harness bounds (`runtime.mjs` `DEFAULT_TIMING`):

| Bound | Value |
| --- | --- |
| Startup | 30 s |
| SSE connect | 10 s |
| Ask | 30 s |
| Debug record | 5 s |
| Completion | 60 s |
| Settle | 1 s |
| Probe | 10 s |
| V2 inventory poll | 15 s |
| Listener close confirmation (`listenerCloseMs`) | 1 s |
| Supervisor TERM grace, then KILL wait | 3 s + 3 s |
| Fixture sleep command | 30 s |
| Provider call budget per scenario | 12 |
| SSE event size | 1 MiB |
| Provider request body | 4 MiB |

## Known limits

- **Sandbox:** viability is unknown (`sandbox-exec` is deprecated). The Mach
  services and the IPv6 and Unix-socket semantics are unproven. A failed
  preflight stops the run; the profile is never relaxed to get past it.
- **Unix socket path limit:** the 103-byte guard is a conservative Darwin
  harness limit, not a portable Unix claim. Whether the long path caused the
  failed pilot's `EADDRINUSE` was not reproduced. Unit tests exercise the
  guard and the listener close contract only with injected fakes (no real
  socket, no `createServer` bind).
- **Retention gate coverage boundary:** the gate covers the processes the
  harness knows about from creation lineage:
  - owned process groups
  - every pid the supervisor spawned
  - pids that fixture commands recorded, including in-flight `.tmp-<pid>` records

  How it decides:
  - **Liveness has three states.** Only ESRCH proves a pid gone. EPERM counts as
    alive, and any other error is "unknown".
  - **The root is kept** (and nothing is signaled) when any of these holds:
    - an owned group is alive
    - a lineage pid is alive or its state is unknown
    - the record directory that prepare created is missing
    - a record is malformed
    - the record directory has an unexpected entry
  - **A record directory that is absent** is legitimate only when prepare never
    created it. **An empty one** is legitimate when no command has run. Neither
    case fabricates a record.
  - **A kept root is a cleanup failure.** The row fails and the matrix stops.
    Evidence has already been collected, and nothing else is deleted.

  UNVERIFIED: a descendant the host itself starts in a new session without
  recording itself is outside this coverage. The gate makes no claim that all
  escaped processes are gone, and it does not scan working directories to
  prove a negative. A future Gate 3 recipe may need a conservative retention
  step if this matters there.
- **Host tool processes:** a host may spawn tool processes in their own group,
  outside the supervisor's reach. The cancel scenario verifies those pids
  exit, and the fixture sleep is bounded at 30 s.
- **Ports:** allocation has a small bind race between choosing a port and the
  host binding it.
- **Probe network operations** (`http-get`, `connect`, `connect-unix`) have
  never run. The `fake-provider.mjs` `serve()` and `main()` have never been
  observed to run: the second pilot attempt launched the provider, but whether
  its entrypoint started is unknown (Amendment A3). Unit tests make no sockets.
- **Unknown until tested:** runtime HOME equivalence between the plugin and
  executed commands, host readiness, and V1 install fast-path behavior.
