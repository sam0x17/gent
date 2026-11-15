// Native Claude function hooks supply lifecycle and input provenance. Rust
// owns configuration, binding credentials, permissions and durable claims.
// CONFIG is prepended by Gent's managed installer; it contains no secrets.
let timer;
let polling = false;
let pending;
let admitted;

async function bridge($, session, operation) {
  const result = await $.process.run([
    CONFIG.binary, '--home', CONFIG.home, '--json', 'integration',
    'claude-wake', '--config-dir', CONFIG.directory,
  ], {
    stdin: JSON.stringify({installation_id: CONFIG.installation_id,
      session_id: session, operation}),
    timeoutMs: 35000,
  });
  if (result.exitCode !== 0 || result.stdout.length > 4096)
    throw new Error('Gent bridge unavailable');
  return JSON.parse(result.stdout);
}

async function poll($) {
  if (polling || pending || admitted) return;
  polling = true;
  try {
    const session = await $.session.id();
    const answer = await bridge($, session, {action: 'claim'});
    if (!answer.dispatch) return;
    const item = answer.dispatch;
    if (item.session_id !== session || await $.session.id() !== session) return;
    pending = item;
    // The host queues plugin input until idle and holds it after explicit
    // interruption. Never set asUser, and never retry a rejected/lost call.
    void $.prompt.submit({text: item.text}).then(result => {
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
    // Preserve uncertainty in the Rust journal. Polls can discover later
    // messages but never acquire the same committed claim a second time.
  } finally {
    polling = false;
  }
}

function start($) {
  if (!timer) timer = $.clock.every(5000, () => poll($));
}
export function register(on) {
  on('session.start', ($, event, next) => {
    start($);
    return next(event);
  });
  on('classic.UserPromptSubmit', async ($, event, next) => {
    start($);
    if (!event.prompt.startsWith('Gent has a pending message.'))
      return next(event);
    const item = pending;
    if (!item || event.prompt !== item.text)
      return {block: 'Gent notification has no matching pending dispatch.'};
    if (event.session_id !== item.session_id || await $.session.id() !== item.session_id)
      return {block: 'Gent notification belongs to another conversation.'};
    const answer = await bridge($, item.session_id, {action: 'check',
      message_id: item.message_id, attempt_id: item.attempt_id});
    if (!answer.eligible || pending !== item || await $.session.id() !== item.session_id)
      return {block: 'Gent dispatch is no longer available for this conversation.'};
    item.guarded = true;
    admitted = item;
    return next(event);
  }).catch(() => ({block: 'Gent could not validate this notification.'}));

  on('turn.start', async ($, event, next) => {
    const item = admitted;
    if (!event.agentId) admitted = undefined;
    // Only a guarded plugin prompt can supply this unique attempt marker. The
    // native host frames plugin text, so match the entire original text within
    // its frame. A callback lost during unload leaves the claim uncertain.
    if (item?.guarded && !event.agentId && event.text.includes(item.text)
        && await $.session.id() === item.session_id) {
      item.guarded = false;
      void bridge($, item.session_id, {action: 'submitted', message_id: item.message_id,
        attempt_id: item.attempt_id, turn_id: event.turnId}).catch(() => {});
    }
    return next(event);
  });
}
