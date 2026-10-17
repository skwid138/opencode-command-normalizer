// Normalizer scenarios for the real-host matrix and the evaluators that judge
// collected evidence. Evaluators are strict: missing, extra, duplicated, or
// mismatched evidence fails. Prompt admission is never completion; an idle
// session with no terminal tool result is never success.
//
// Evidence ordering is the arrival order of `evidence.events` (the executor
// appends a { kind: "submitted" } marker when it sends the prompt).

const PROBE = "rh-probe";
const SLEEP = "rh-sleep";

/** Fixture commands the host's shell runs, by name under the fixture bin dir. */
export const FIXTURE_COMMANDS = Object.freeze([PROBE, SLEEP]);
/** The only executables the fixture scripts invoke, by explicit absolute path (never via PATH). */
export const SCRIPT_SYSTEM_EXECUTABLES = Object.freeze(["/bin/sh", "/bin/mv", "/bin/sleep"]);

/** Exact exec allowances the fixture needs: its commands plus the system tools they call. */
export function fixtureExecutables(fixtureBin) {
  return [...FIXTURE_COMMANDS.map((name) => `${fixtureBin}/${name}`), ...SCRIPT_SYSTEM_EXECUTABLES];
}
const SLEEP_SECONDS = 30;
export const EXEC_RECORD_MAGIC = "rh-exec-v1";

/**
 * Literal argument tail every probe command carries. Single-quoted in the
 * command, so the shell passes it through verbatim: a quoted `~`, a quoted
 * `$HOME`, an empty argument, and an embedded space. The normalizer only ever
 * rewrites argv0; shell expansion of argv0 is the shell's job, not evidence
 * of normalization (that comes from audit text and permission patterns).
 */
export const TAIL_ARGS = Object.freeze(["~/lit", "$HOME/lit", "", "a b"]);
const TAIL = TAIL_ARGS.map((arg) => `'${arg}'`).join(" ");

// Each execution writes one NUL-separated record (NUL cannot occur in argv,
// HOME, or a path), atomically via rename:
//   magic, pid, HOME, physical cwd, argc, $0, argv...
function recordLines(recordDir) {
  return [
    `rd='${recordDir}'`,
    't="$rd/.tmp-$$"',
    `{ printf '${EXEC_RECORD_MAGIC}\\0%s\\0%s\\0%s\\0%s\\0%s\\0' "$$" "$HOME" "$(pwd -P)" "$#" "$0"; for a in "$@"; do printf '%s\\0' "$a"; done; } > "$t" && /bin/mv "$t" "$rd/exec-$$.rec"`,
  ];
}

/** POSIX sh fixture command: records an unambiguous execution record, prints the nonce. */
export function probeScript({ recordDir }) {
  return ["#!/bin/sh", ...recordLines(recordDir), `printf 'RH-PROBE %s\\n' "$1"`, ""].join("\n");
}

/** Bounded fixture command for cancel: records, then sleeps a fixed, finite time. */
export function sleepScript({ recordDir }) {
  return ["#!/bin/sh", ...recordLines(recordDir), `exec /bin/sleep ${SLEEP_SECONDS}`, ""].join("\n");
}

/** Parses one execution record; returns { malformed } instead of guessing. */
export function parseExecRecord(buffer) {
  const fields = buffer.toString("utf8").split("\0");
  if (fields.at(-1) !== "") return { malformed: "record is not NUL-terminated" };
  fields.pop();
  if (fields[0] !== EXEC_RECORD_MAGIC || fields.length < 6) return { malformed: "bad magic or truncated header" };
  const [, pid, home, cwd, argcText, executable, ...argv] = fields;
  const argc = Number(argcText);
  if (!/^\d+$/.test(pid) || !/^\d+$/.test(argcText)) return { malformed: "pid or argc is not numeric" };
  if (argc !== argv.length) return { malformed: `argc ${argc} does not match ${argv.length} recorded arguments` };
  return { tool: executable.split("/").pop(), executable, pid: Number(pid), home, cwd, argc, argv };
}

export function scenarioMatrix({ fixture, nonce }) {
  const home = fixture.home;
  const logs = {
    auditLogPath: `${fixture.logs}/audit.log`,
    debugLogPath: `${fixture.logs}/debug.log`,
    decisionsLogPath: `${fixture.logs}/decisions.log`,
  };
  const plugin = (extra = {}) => ({ options: { ...logs, ...extra } });
  const absProbe = `${home}/bin/${PROBE}`;
  const abs = `${absProbe} ${nonce} ${TAIL}`;
  const argv = [nonce, ...TAIL_ARGS];
  const askAll = [{ pattern: "*", effect: "ask" }];
  const allowProbe = [...askAll, { pattern: `${absProbe} *`, effect: "allow" }];
  const denyProbe = [...askAll, { pattern: `${absProbe} *`, effect: "deny" }];
  const single = (id, fields) => ({ kind: "single", id, toolCalls: [fields.command], replies: [], ...fields });
  const ran = { tool: PROBE, terminal: "completed", argvs: [argv] };
  const rejected = { tool: PROBE, asks: 1, terminal: "rejected", argvs: [] };

  return [
    single("pilot-ask-once", {
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: askAll,
      replies: ["once"],
      expect: { ...ran, asks: 1, auditTexts: [abs], askPatternIncludes: absProbe },
    }),
    single("baseline-plugin-absent", {
      plugin: null,
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: askAll,
      replies: ["reject"],
      expect: { ...rejected, auditTexts: null, observational: true },
    }),
    single("tilde-allow", {
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: allowProbe,
      expect: { ...ran, asks: 0, auditTexts: [abs] },
    }),
    single("dollar-home-allow", {
      plugin: plugin(),
      command: `$HOME/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: allowProbe,
      expect: { ...ran, asks: 0, auditTexts: [abs] },
    }),
    single("deny-resource", {
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: denyProbe,
      expect: { tool: PROBE, asks: 0, terminal: "denied", argvs: [], auditTexts: [abs] },
    }),
    single("ask-reject", {
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: askAll,
      replies: ["reject"],
      expect: { ...rejected, auditTexts: [abs], askPatternIncludes: absProbe },
    }),
    single("roots-empty", {
      plugin: plugin({ roots: [] }),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: allowProbe,
      replies: ["reject"],
      expect: { ...rejected, auditTexts: [`~/bin/${PROBE} ${nonce} ${TAIL}`] },
    }),
    single("braces-off", {
      plugin: plugin({ roots: ["~/bin"], expandBraceHome: false }),
      command: `\${HOME}/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: allowProbe,
      replies: ["reject"],
      expect: { ...rejected, auditTexts: [`\${HOME}/bin/${PROBE} ${nonce} ${TAIL}`] },
    }),
    single("braces-on", {
      plugin: plugin({ roots: ["~/bin"], expandBraceHome: true }),
      command: `\${HOME}/bin/${PROBE} ${nonce} ${TAIL}`,
      rules: allowProbe,
      expect: { ...ran, asks: 0, auditTexts: [abs] },
    }),
    {
      kind: "lifecycle",
      id: "lifecycle",
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} ${TAIL}`,
      toolCalls: [`~/bin/${PROBE} ${nonce} ${TAIL}`],
      rules: allowProbe,
      replies: [],
      phases: [
        { name: "active", replies: [], expect: { ...ran, asks: 0, auditTexts: [abs] }, audits: 1 },
        { name: "removed", replies: ["reject"], expect: { ...rejected, auditTexts: null }, audits: 0 },
        { name: "restored", replies: [], expect: { ...ran, asks: 0, auditTexts: [abs] }, audits: 1 },
      ],
      expect: {},
    },
    single("cancel", {
      plugin: plugin(),
      command: `~/bin/${SLEEP} ${nonce} ${TAIL}`,
      rules: [...askAll, { pattern: `${home}/bin/${SLEEP} *`, effect: "allow" }],
      expect: { tool: SLEEP, asks: 0, terminal: "aborted", argvs: [argv], auditTexts: [`${home}/bin/${SLEEP} ${nonce} ${TAIL}`], cancel: true },
    }),
    {
      kind: "single",
      id: "asks-immediate-and-later",
      plugin: plugin(),
      command: `~/bin/${PROBE} ${nonce} first ${TAIL}`,
      toolCalls: [`~/bin/${PROBE} ${nonce} first ${TAIL}`, `~/bin/${PROBE} ${nonce} later ${TAIL}`],
      rules: askAll,
      replies: ["once", "once"],
      expect: {
        ...ran,
        asks: 2,
        argvs: [
          [nonce, "first", ...TAIL_ARGS],
          [nonce, "later", ...TAIL_ARGS],
        ],
        auditTexts: [`${absProbe} ${nonce} first ${TAIL}`, `${absProbe} ${nonce} later ${TAIL}`],
        askPatternIncludes: absProbe,
      },
    },
  ];
}

const forSession = (sessionID) => (event) => event.sessionID === sessionID;

export function evaluateCompletion(evidence, { expectedToolCalls }) {
  const problems = [];
  const events = Array.isArray(evidence.events) ? evidence.events : [];
  if (evidence.promptAccepted !== true) problems.push("prompt was not accepted by the host");
  const submitted = events.findIndex((event) => event.kind === "submitted");
  const connected = events.findIndex((event) => event.kind === "connected");
  if (submitted === -1) problems.push("no submission marker in the event record");
  if (connected === -1 || (submitted !== -1 && connected > submitted)) problems.push("event stream was not connected before submission");
  const after = events.map((event, index) => ({ event, index })).filter(({ index }) => index > submitted);
  const terminals = new Map();
  for (const { event, index } of after) {
    if (event.kind === "tool-terminal" && forSession(evidence.sessionID)(event) && typeof event.callID === "string" && !terminals.has(event.callID)) {
      terminals.set(event.callID, { ...event, index });
    }
  }
  if (terminals.size === 0) problems.push(`no terminal tool result for session ${evidence.sessionID} after submission`);
  else if (terminals.size !== expectedToolCalls) problems.push(`expected ${expectedToolCalls} terminal tool result(s), got ${terminals.size}`);
  if (terminals.size > 0) {
    const last = Math.max(...[...terminals.values()].map((terminal) => terminal.index));
    const idle = after.some(({ event, index }) => index > last && (event.kind === "session-idle" || event.kind === "session-final") && forSession(evidence.sessionID)(event));
    if (!idle) problems.push("no idle or final session event after the last terminal tool result");
  }
  return { complete: problems.length === 0, problems, callIDs: [...terminals.keys()], terminals: [...terminals.values()] };
}

function evaluateExpectation(scenario, expect, replies, evidence, { fixture, nonce }) {
  const completion = evaluateCompletion(evidence, { expectedToolCalls: scenario.toolCalls.length });
  const problems = [...completion.problems];
  const sid = evidence.sessionID;
  const events = evidence.events ?? [];

  const asked = events.filter((event) => event.kind === "permission-asked" && event.sessionID === sid);
  const sent = evidence.replies ?? [];
  for (const terminal of completion.terminals) {
    if (expect.terminal === "completed") {
      if (terminal.status !== "completed" || terminal.failure) {
        problems.push(`terminal for ${terminal.callID} is ${terminal.status}/${terminal.failure}, expected a completed execution`);
      }
      // Local execution is proven by the terminal event plus the execution record, never by a host flag.
      if (terminal.providerExecuted === true) problems.push(`terminal for ${terminal.callID} is provider-executed, not a local built-in tool execution`);
      continue;
    }
    if (terminal.status !== "error" || terminal.failure !== expect.terminal) {
      problems.push(`terminal for ${terminal.callID} is ${terminal.status}/${terminal.failure} (${JSON.stringify(terminal.error ?? null)}), expected a${expect.terminal === "aborted" ? "n" : ""} ${expect.terminal} ${expect.terminal === "aborted" ? "cancel" : "permission"} outcome`);
    }
    if (terminal.providerExecuted === true) problems.push(`terminal for ${terminal.callID} is provider-executed for a blocked call`);
    if (expect.terminal === "rejected") {
      const ask = asked.find((candidate) => candidate.callID === terminal.callID);
      const reply = ask && sent.find((candidate) => candidate.requestID === ask.requestID);
      if (!ask || !reply || reply.decision !== "reject" || reply.accepted !== true) problems.push(`no explicit reject reply correlated to call ${terminal.callID}`);
    }
  }

  const executions = evidence.executions ?? [];
  for (const entry of executions) if (entry.malformed) problems.push(`malformed execution record: ${entry.malformed}`);
  const mine = executions.filter((entry) => !entry.malformed && entry.argv?.[0] === nonce);
  if (mine.length !== expect.argvs.length) problems.push(`expected ${expect.argvs.length} execution(s) of ${expect.tool} with the run nonce, got ${mine.length}`);
  for (const entry of mine) {
    if (entry.executable !== `${fixture.home}/bin/${expect.tool}`) problems.push(`execution executable ${entry.executable} is not ${fixture.home}/bin/${expect.tool}`);
    if (entry.home !== fixture.home) problems.push(`execution HOME ${entry.home} is not the fixture home`);
    if (entry.cwd !== fixture.project) problems.push(`execution cwd ${entry.cwd} is not the fixture project`);
    if (entry.argc !== entry.argv.length) problems.push(`execution argc ${entry.argc} does not match argv length ${entry.argv.length}`);
  }
  const key = (list) => JSON.stringify(list);
  const actualArgv = mine.map((entry) => key(entry.argv)).sort();
  const expectedArgv = expect.argvs.map(key).sort();
  if (mine.length === expect.argvs.length && key(actualArgv) !== key(expectedArgv)) problems.push(`execution argv ${actualArgv.join(" | ")} != expected ${expectedArgv.join(" | ")}`);

  if (asked.length !== expect.asks) problems.push(`expected ${expect.asks} ask(s), got ${asked.length}`);
  if (sent.length !== replies.length) problems.push(`expected ${replies.length} controlled repl(ies), sent ${sent.length}`);
  asked.forEach((ask, index) => {
    const reply = sent[index];
    if (!reply || reply.requestID !== ask.requestID) problems.push(`no controlled reply for ask ${ask.requestID}`);
    else {
      if (reply.decision !== replies[index]) problems.push(`reply ${reply.requestID} decision ${reply.decision} != ${replies[index]}`);
      if (reply.accepted !== true) problems.push(`reply ${reply.requestID} was not accepted by the host`);
      if (scenario.plugin && reply.afterDebugRecord !== true) problems.push(`reply ${reply.requestID} was sent before the plugin debug record "permission asked cached"`);
    }
    const repliedEvents = events.filter((event) => event.kind === "permission-replied" && event.sessionID === sid && event.requestID === ask.requestID);
    if (repliedEvents.length !== 1 || repliedEvents[0].reply !== replies[index]) {
      problems.push(`expected one permission.replied ${replies[index]} for ${ask.requestID}, got ${JSON.stringify(repliedEvents.map((event) => event.reply))}`);
    }
    if (expect.askPatternIncludes && !(ask.patterns ?? []).some((pattern) => pattern.includes(expect.askPatternIncludes))) {
      problems.push(`ask ${ask.requestID} patterns ${JSON.stringify(ask.patterns)} do not include ${expect.askPatternIncludes}`);
    }
    if (scenario.plugin && expect.auditTexts) {
      const decision = (evidence.decisions ?? []).find((record) => record.sessionID === sid && record.requestID === ask.requestID);
      if (!decision) problems.push(`missing decision record for (${sid}, ${ask.requestID})`);
      else if (decision.callID !== ask.callID || decision.reply !== replies[index]) problems.push(`decision record for ${ask.requestID} does not match the ask/reply`);
    }
  });

  const audit = (evidence.audit ?? []).filter((record) => record.sessionID === sid);
  if (!expect.auditTexts) {
    if (audit.length > 0) problems.push(`plugin absent but ${audit.length} audit record(s) for session ${sid}`);
  } else {
    const texts = [];
    for (const callID of completion.callIDs) {
      const records = audit.filter((record) => record.callID === callID);
      if (records.length !== 1) problems.push(`audit records for (${sid}, ${callID}): ${records.length}, expected 1`);
      if (records[0]) texts.push(records[0].command_node_text);
    }
    const stray = audit.filter((record) => !completion.callIDs.includes(record.callID));
    if (stray.length > 0) problems.push(`audit records for unexpected callIDs: ${stray.map((record) => record.callID).join(", ")}`);
    if (completion.callIDs.length > 0 && JSON.stringify([...texts].sort()) !== JSON.stringify([...expect.auditTexts].sort())) {
      problems.push(`audit command text ${JSON.stringify(texts)} != expected ${JSON.stringify(expect.auditTexts)}`);
    }
  }

  const provider = evidence.provider ?? {};
  if (provider.budgetExceeded !== false) problems.push("provider call budget exceeded or unreported");
  if (provider.rejected) problems.push(`provider rejected ${provider.rejected} request(s)`);
  if (provider.toolNotAdvertised) problems.push(`built-in tool was not advertised in ${provider.toolNotAdvertised} request(s)`);
  const issued = (provider.ledger ?? []).filter((entry) => entry.kind === "tool-call").length;
  if (issued !== scenario.toolCalls.length) problems.push(`provider tool calls issued: ${issued}, expected ${scenario.toolCalls.length}`);

  if (expect.cancel) {
    const cancel = evidence.cancel;
    if (!cancel || cancel.requested !== true || cancel.accepted !== true) problems.push("cancel was not requested and accepted");
    if (mine.some((entry) => !Number.isInteger(entry.pid))) problems.push("cancelled execution did not record its pid");
    const alive = cancel?.childPidsAliveAfter ?? ["unknown"];
    if (alive.length > 0) problems.push(`fixture child process(es) still alive after cancel: ${alive.join(", ")}`);
  }

  return { problems, asked, completion };
}

export function evaluateScenario(scenario, evidence, context) {
  if (scenario.kind !== "single") throw new Error(`evaluateScenario handles single scenarios; use evaluateLifecycle for ${scenario.id}`);
  const { problems, asked } = evaluateExpectation(scenario, scenario.expect, scenario.replies, evidence, context);
  const result = { id: scenario.id, status: problems.length === 0 ? "pass" : "fail", problems };
  if (scenario.expect.observational) result.observed = { patterns: asked.map((ask) => ask.patterns) };
  return result;
}

/** Judges one lifecycle phase with the phase's own expectation. */
export function evaluateLifecyclePhase(scenario, phase, evidence, context) {
  const { problems, completion } = evaluateExpectation({ ...scenario, plugin: phase.name === "removed" ? null : scenario.plugin }, phase.expect, phase.replies, evidence, context);
  return { name: phase.name, status: problems.length === 0 ? "pass" : "fail", problems, callID: completion.callIDs[0] ?? null };
}

const LIFECYCLE = [
  ["active", 1],
  ["removed", 0],
  ["restored", 1],
];

/** Cardinality per actual callID: 1 active, 0 removed, 1 restored (detects duplicate idempotent hooks). */
export function evaluateLifecycle(phases) {
  const problems = [];
  const names = phases.map((phase) => phase.name);
  if (JSON.stringify(names) !== JSON.stringify(LIFECYCLE.map(([name]) => name))) problems.push(`lifecycle phases must be active, removed, restored; got ${names.join(", ")}`);
  for (const [name, expected] of LIFECYCLE) {
    const phase = phases.find((candidate) => candidate.name === name);
    if (!phase) continue;
    if (typeof phase.callID !== "string") problems.push(`${name}: no actual callID`);
    const count = (phase.audit ?? []).filter((record) => record.sessionID === phase.sessionID && record.callID === phase.callID).length;
    if (count !== expected) problems.push(`${name}: expected ${expected} audit record(s) for (${phase.sessionID}, ${phase.callID}), got ${count}`);
    if (phase.inventory && phase.inventory.ok !== true) problems.push(`${name}: inventory: ${phase.inventory.problems.join("; ")}`);
    if (phase.scenario?.status !== "pass") problems.push(`${name}: scenario: ${(phase.scenario?.problems ?? ["missing"]).join("; ")}`);
  }
  return { status: problems.length === 0 ? "pass" : "fail", problems };
}
