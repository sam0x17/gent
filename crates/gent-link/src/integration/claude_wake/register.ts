// Native hooks supply input provenance and final answers. Rust owns bindings,
// permissions and durable Gent reply identities. CONFIG contains no secrets.
let timer;
let polling = false;
let activeTurn;
let resuming;
let generation = 0;
let writes = Promise.resolve();
const cancelled = new Set();
const babysitterKey = session => `gent-babysitter/v2/${CONFIG.installation_id}/${session}`;
const resumePrefix = 'Continue working on the current goal.\n\n[Gent goal resume ';

// Serialize store mutations: a slow failure write must precede a later input's deletion.
function writeStall(op) {
  writes = writes.then(op).then(() => true, () => false);
  return writes;
}
function discardStall($, session) {
  cancelled.add(session);
  return writeStall(() => $.store.delete(babysitterKey(session)));
}
function cancelStall($, session) {
  generation++;
  activeTurn = undefined;
  return discardStall($, session);
}
async function captureFailure($, event) {
  const turn = activeTurn;
  const before = generation;
  const observed_ms = Date.now();
  if (!turn || event.agent_id || typeof event.transcript_path !== 'string') return;
  const session = await turn.session;
  if (event.session_id !== session || before !== generation) return;
  // Claude can omit error_details. On StopFailure it renders the provider
  // error as the hook's final message, prefixed "API Error:".
  const rendered = event.last_assistant_message;
  const details = event.error_details ||
    (typeof rendered === 'string' && rendered.startsWith('API Error: ') ? rendered : '');
  const operation = {action:'babysit_capture', turn:turn.id, started_ms:turn.started,
    path:event.transcript_path, observed_ms,
    code:String(event.error || '').slice(0,128), details:String(details).slice(0,4096)};
  async function observe(retry) {
    if (before !== generation || await $.session.id() !== session) return;
    const answer = await bridge($, session, operation).catch(() => ({pending:true}));
    if (await $.session.id() !== session || before !== generation) return;
    if (answer.failure) {
      const stored = await writeStall(() => $.store.set(babysitterKey(session), answer.failure));
      if (stored && before === generation) cancelled.delete(session);
    } else if (answer.pending && retry < 2) {
      // Claude may flush the goal and native error after StopFailure returns.
      // Both retries use the original turn, observation time and input generation.
      $.clock.after(retry === 0 ? 500 : 2000, () => observe(retry+1).catch(() => {}));
    }
  }
  await observe(0);
}
async function recoverGoal($, session) {
  const before = generation;
  await writes;
  if (before !== generation || cancelled.has(session)) return;
  const failure = await $.store.get(babysitterKey(session));
  if (!failure || before !== generation) return;
  if (Date.now()/1000 - failure.failed_at > 7200) {
    await cancelStall($,session);
    return;
  }
  const answer = await bridge($, session, {action:'babysit_claim', failure});
  if (await $.session.id() !== session || before !== generation) return;
  if (answer.obsolete) { await cancelStall($,session); return; }
  if (!answer.claim) return;
  // A committed claim cannot be repeated, even if submission or its reply is lost.
  cancelled.add(session);
  await writeStall(() => $.store.delete(babysitterKey(session)));
  const check = await bridge($, session, {action:'babysit_check', attempt:answer.claim, failure});
  if (check.text !== resumePrefix + CONFIG.installation_id + ' ' + answer.claim + ']'
      || await $.session.id() !== session || before !== generation) return;
  const ticket = {session, before, text:check.text};
  resuming = ticket;
  try {
    const result = await $.prompt.submit({text:ticket.text,asUser:true});
    if (!result.drop && result.text === ticket.text && result.origin?.kind === 'plugin'
        && result.origin.name === 'gent-wake' && result.origin.asUser === true)
      await bridge($,session,{action:'babysit_submitted',attempt:answer.claim});
  } finally {
    if (resuming === ticket) resuming = undefined;
  }
}
let pending;
let admitted;
let flushCursor;
const prefix = session => `gent-direct-v1/${CONFIG.installation_id}/${session}/`;

async function bridge($, session, operation) {
  const result = await $.process.run([
    CONFIG.binary, '--home', CONFIG.home, '--json', 'integration',
    'claude-wake', '--config-dir', CONFIG.directory,
  ], {
    stdin: JSON.stringify({installation_id: CONFIG.installation_id,
      session_id: session, operation}),
    timeoutMs: 35000,
  });
  if (result.exitCode !== 0 || result.stdout.length > 512 * 1024)
    throw new Error('Gent bridge unavailable');
  return JSON.parse(result.stdout);
}

async function routes($, session) {
  return (await $.store.keys()).filter(key => key.startsWith('gent-direct-v1/')
    && key.split('/').length === 4 && key.split('/')[2] === session).sort();
}

async function flush($, session) {
  // Old installation generations may retain a captured answer. Only the Rust
  // journal can accept its existing attempt and exact native turn; never replay input.
  const keys = await routes($, session);
  const remaining = keys.filter(key => !flushCursor || key > flushCursor);
  const batch = (remaining.length ? remaining : keys).slice(0, 16);
  flushCursor = batch.at(-1);
  for (const key of batch) {
    const item = await $.store.get(key);
    if (!item || item.session_id !== session || !item.turn_id) continue;
    try {
      await bridge($, session, {action:'observe', message_id:item.message_id,
        attempt_id:item.attempt_id, turn_id:item.turn_id});
      if (item.automatic_reply && item.answer === undefined) continue;
      if (item.automatic_reply) {
        await bridge($, session, {action:'complete', message_id:item.message_id,
          attempt_id:item.attempt_id, turn_id:item.turn_id, text:item.answer});
      }
      await $.store.delete(key);
    } catch (_) {
      // Keep the host result for an identical retry. Never submit its input again.
    }
  }
}

async function poll($) {
  if (polling) return;
  polling = true;
  try {
    const session = await $.session.id();
    await flush($, session);
    if (pending || admitted) return;
    try { await recoverGoal($,session); } catch (_) { /* Retry only before a durable claim. */ }
    const answer = await bridge($, session, {action:'claim_direct'});
    if (!answer.dispatch) return;
    const item = answer.dispatch;
    if (item.session_id !== session || await $.session.id() !== session) return;
    pending = item;
    // Keep native plugin origin and native busy/interruption handling.
    void $.prompt.submit({text:item.text}).then(result => {
      if (result.drop) {
        if (admitted === item) admitted = undefined;
        return;
      }
      if (result.text !== item.text || result.origin?.kind !== 'plugin'
          || result.origin.name !== 'gent-wake' || result.origin.asUser)
        throw new Error('Unexpected native Gent input result');
    }).catch(() => {
      if (admitted === item) admitted = undefined;
    }).finally(() => {
      if (pending === item) pending = undefined;
    });
  } catch (_) {
    // Committed claims stay uncertain; no new claim can repeat their input.
  } finally {
    polling = false;
  }
}

function nativeInput(text, input) {
  const wrapped = `The gent-wake plugin sent a message:\n${input}`;
  const suffix = "\n\nThis is how Claude Code surfaces a prompt a plugin submits between turns — it starts this turn in the user's place. Address the message above.";
  return text === wrapped || text === wrapped + suffix;
}

function start($) {
  if (!timer) timer = $.clock.every(5000, () => poll($));
}
export function register(on) {
  on('session.start', ($, event, next) => {
    start($);
    // Discard legacy raw failures; they carry no failure-time provenance.
    void (async () => {
      for (const key of await $.store.keys())
        if (key.startsWith('gent-babysitter/v1/')) await $.store.delete(key);
    })().catch(() => {});
    return next(event);
  });
  on('prompt.submit', async ($, event, next) => {
    if (event.origin?.name === 'gent-wake' && event.origin.kind === 'plugin'
        && event.origin.asUser === true && event.text.startsWith(resumePrefix)) {
      if (!resuming || resuming.before !== generation || resuming.text !== event.text)
        return {drop:'Gent goal continuation is no longer eligible.'};
    } else if (!event.agentId) {
      const before = ++generation;
      activeTurn = undefined;
      void Promise.resolve().then(() => $.session.id()).then(session => {
        if (before === generation) return discardStall($,session);
      }).catch(() => {});
    }
    return next(event);
  });
  on('classic.StopFailure', async ($,event,next) => {
    const observation = captureFailure($,event).catch(() => {});
    const result = await next(event);
    await observation;
    return result;
  });
  on('classic.UserPromptSubmit', async ($, event, next) => {
    start($);
    if (event.prompt.startsWith(resumePrefix)) {
      if (event.agent_id || !resuming || resuming.before !== generation
          || resuming.session !== event.session_id || resuming.text !== event.prompt)
        return {block:'Gent goal continuation is no longer eligible.'};
      return next(event); // The independent native guard checks the transcript and consumes the ticket.
    }
    if (!event.agent_id) void cancelStall($,event.session_id);
    if (!event.prompt.includes('\n\n[Gent delivery ')
        && !event.prompt.startsWith('Gent has a pending message.')) return next(event);
    const item = pending;
    if (!item || event.prompt !== item.text)
      return {block:'Gent input has no matching pending dispatch.'};
    if (event.session_id !== item.session_id || await $.session.id() !== item.session_id)
      return {block:'Gent input belongs to another conversation.'};
    const answer = await bridge($, item.session_id, {action:'check_direct',
      message_id:item.message_id, attempt_id:item.attempt_id});
    if (!answer.eligible || answer.text !== item.text || pending !== item
        || await $.session.id() !== item.session_id)
      return {block:'Gent message is no longer available for this conversation.'};
    item.guarded = true;
    admitted = item;
    return next(event);
  }).catch(() => ({block:'Gent could not validate this input.'}));

  on('turn.start', async ($, event, next) => {
    const item = admitted;
    if (!event.agentId) {
      admitted = undefined;
      const before = ++generation;
      const session = Promise.resolve().then(() => $.session.id()).catch(() => undefined);
      activeTurn = {session, id:event.turnId, started:Date.now()};
      // An unavailable babysitter store/session must never hold a host turn.
      void session.then(id => {
        if (id && before === generation) return discardStall($,id);
      });
    }
    if (item?.guarded && !event.agentId && nativeInput(event.text, item.text)
        && await $.session.id() === item.session_id) {
      item.guarded = false;
      item.turn_id = event.turnId;
      // Native store survives module reloads and daemon outages. It contains no
      // credentials and is scoped to this installation, session and native turn.
      await $.store.set(prefix(item.session_id) + event.turnId, item);
      await flush($, item.session_id);
    }
    return next(event);
  });

  on('turn.complete', async ($, event, next) => {
    const result = await next(event);
    if (event.agentId) return result;
    const session = await $.session.id();
    if ((event.isAborted || event.reason !== 'error') && activeTurn?.id === event.turnId)
      void cancelStall($,session);
    const keys = (await routes($, session)).filter(key => key.endsWith('/' + event.turnId));
    if (keys.length !== 1) return result;
    const key = keys[0];
    const item = await $.store.get(key);
    if (item?.turn_id !== event.turnId || !item.automatic_reply) return result;
    item.answer = event.isAborted
      ? 'The remote turn was interrupted. Gent has not repeated the request.'
      : event.reason === 'error'
        ? 'The remote turn failed. Gent has not repeated the request.'
        : result.text;
    if (typeof item.answer !== 'string') return result;
    if (!item.answer) item.answer = 'The remote turn completed without a text response.';
    await $.store.set(key, item);
    await flush($, session);
    return result;
  });
}
