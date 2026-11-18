// Native hooks supply input provenance and final answers. Rust owns bindings,
// permissions and durable Gent reply identities. CONFIG contains no secrets.
let timer;
let polling = false;
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
  on('session.start', ($, event, next) => { start($); return next(event); });
  on('classic.UserPromptSubmit', async ($, event, next) => {
    start($);
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
    if (!event.agentId) admitted = undefined;
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
