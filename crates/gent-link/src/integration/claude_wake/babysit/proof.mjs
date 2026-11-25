// Synthetic Claude host. The Rust fixture answers process.run over private pipes.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {appendFileSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createInterface} from 'node:readline';

const [directory, session] = process.argv.slice(2);
const project = join(directory, 'projects', 'private-project');
mkdirSync(project, {recursive:true});
const transcript = join(project, session + '.jsonl');
const moduleText = readFileSync(join(directory, 'skills/gent-wake/hooks/register.ts'), 'utf8');
const responses = createInterface({input:process.stdin})[Symbol.asyncIterator]();
const store = new Map();
const actions = [];
const prompts = [];
const hostResult = {host:true};
let calls = new Map(), tick, beforeCheck, beforeCaptureReturn, failDelete = false;
let offline = false, queuedInput, skipOwnHooks = false, loseResult = false;
const guards = [];
const timers = [];

async function requestBridge(request) {
  process.stdout.write(JSON.stringify(request) + '\n');
  return JSON.parse((await responses.next()).value);
}

const $ = {
  session: {id:async () => session},
  store: {
    get:async key => structuredClone(store.get(key)),
    set:async (key,value) => { store.set(key, structuredClone(value)); },
    delete:async key => { if (failDelete) throw Error('store unavailable'); store.delete(key); },
    keys:async () => [...store.keys()],
  },
  clock: {every: (_ms, fn) => { tick = fn; return 1; }, after: (_ms, fn) => timers.push(fn)},
  process: {run: async (_argv, options) => {
    const request = JSON.parse(options.stdin);
    const op = request.operation.action;
    actions.push(op);
    if (offline) throw Error('unavailable');
    if (op === 'babysit_check' && beforeCheck) await beforeCheck();
    const response = await requestBridge(request);
    assert.equal(response.exitCode, 0, 'fixture bridge rejected ' + op);
    if (op === 'babysit_capture' && beforeCaptureReturn) await beforeCaptureReturn();
    return response;
  }},
  prompt: {submit:async input => {
    queueRow('enqueue');
    if (queuedInput) await queuedInput();
    queueRow('dequeue');
    const event = {...input, origin:{kind:'plugin',name:'gent-wake',asUser:true}};
    const classic = {hook_event_name:'UserPromptSubmit', session_id:session,
      transcript_path:transcript, prompt:input.text};
    const guard = async () => {
      const reply = await requestBridge({guard_event:classic});
      guards.push(reply.exitCode);
      if (reply.exitCode !== 0 || !JSON.parse(reply.stdout).continue) return {drop:'guard'};
      prompts.push(input);
      return loseResult ? {text:input.text} : event;
    };
    if (skipOwnHooks) return guard();
    const result = await calls.get('prompt.submit')($, event, () =>
      calls.get('classic.UserPromptSubmit')($, classic, guard));
    return result.block ? {drop:result.block} : result;
  }},
};
async function emit(name, event) {
  let count = 0;
  const result = await calls.get(name)($, event, async actual => {
    assert.equal(actual, event);
    count++;
    return hostResult;
  });
  assert.equal(count, 1, 'native event swallowed: ' + name);
  assert.equal(result, hostResult);
}
async function reload() {
  calls = new Map();
  const url = 'data:text/javascript;base64,' + Buffer.from(moduleText).toString('base64');
  const {register} = await import(url + '#' + randomUUID());
  register((name, handler) => {
    calls.set(name,handler);
    return {catch(fallback) { calls.set(name, (...args) => handler(...args).catch(fallback)); }};
  });
  await emit('session.start',{});
}
function row(fields) {
  appendFileSync(transcript, JSON.stringify({sessionId:session, uuid:randomUUID(),
    timestamp:new Date().toISOString(), ...fields}) + '\n');
}
function queueRow(operation) {
  appendFileSync(transcript, JSON.stringify({type:'queue-operation',operation,
    timestamp:new Date().toISOString(),sessionId:session}) + '\n');
}
const human = () => emit('classic.UserPromptSubmit',{session_id:session,prompt:'ordinary private input'});
const condition = 'private goal ' + randomUUID();
const markGoal = () => row({type:'attachment', attachment:{type:'goal_status', met:false, condition}});
async function turn() {
  await human();
  row({type:'user',message:{role:'user',content:'private user text'}});
  const turnId = randomUUID();
  await emit('turn.start',{turnId});
  return turnId;
}
const providerError = () => row({type:'assistant',isApiErrorMessage:true,message:{content:'private API body'}});
async function failure(error='invalid_request',extra={}) {
  if (!extra.agent_id) providerError();
  await emit('classic.StopFailure',{session_id:session,transcript_path:transcript,error,
    error_details:"private API body: Invalid value in input[0].tools[0].type; supported values include function",
    ...extra});
}
async function prepare() {
  store.clear();
  writeFileSync(transcript,'');
  await reload();
  markGoal();
  await turn();
  await failure();
  assert.equal(store.size,1);
  const [[key,record]] = store;
  assert.ok(key.startsWith('gent-babysitter/v2/'));
  assert.deepEqual(Object.keys(record).sort(), ['failed_at','reason','source','turn']);
  assert.equal(record.reason,'tool_schema');
  assert.doesNotMatch(JSON.stringify(record), /private|supported values|transcript_path|\.jsonl/i);
}

await prepare();
offline = true;
await tick();
assert.equal(prompts.length,0);
offline = false;
// Lose every in-memory hook and restore solely from the sanitized record.
await reload();
await tick();
assert.equal(prompts.length,1);
assert.equal(prompts[0].asUser,true);
assert.match(prompts[0].text,/^Continue working on the current goal\.\n\n\[Gent goal resume [a-f0-9-]{36} [a-f0-9-]{36}\]$/);
assert.deepEqual(guards,[0]);
assert.ok(actions.includes('babysit_submitted'));
assert.notEqual((await requestBridge({guard_event:{hook_event_name:'UserPromptSubmit',
  session_id:session, prompt:prompts[0].text}})).exitCode,0);
await reload();
await tick();
assert.equal(prompts.length,1);

for (const intervening of [
  () => row({type:'user',message:{role:'user',content:'changed while offline'}}),
  () => row({type:'queue-operation',operation:'enqueue',content:'queued while offline'}),
  markGoal, // new goal with identical words and a new native attachment identity
  () => row({type:'attachment',attachment:{type:'goal_status',met:true}}),
]) {
  await prepare();
  intervening();
  await reload();
  await tick();
  assert.equal(store.size,0);
  assert.equal(prompts.length,1);
}

// Put a new goal between the authorized claim and the last pre-submit check.
// Use a different goal from the successful case to avoid its legitimate backoff.
await reload();
writeFileSync(transcript,'');
row({type:'attachment',attachment:{type:'goal_status',met:false,condition:'private other goal'}});
await turn();
await failure();
const checks = actions.filter(a=>a==='babysit_check').length;
beforeCheck = async () => markGoal();
await tick();
beforeCheck = undefined;
assert.equal(actions.filter(a=>a==='babysit_check').length, checks+1);
assert.equal(prompts.length,1);

// The host queued our as-user prompt and saw genuine user input first.
row({type:'attachment',attachment:{type:'goal_status',met:false,condition:'private queued goal'}});
await turn();
await failure('rate_limit');
const submissions = actions.filter(a=>a==='babysit_submitted').length;
let queueVisited = false;
queuedInput = async () => {
  queueVisited = true;
  await emit('prompt.submit',{text:'queued human interruption',origin:{kind:'composer'}});
};
await tick();
queuedInput = undefined;
assert.equal(queueVisited,true);
assert.equal(prompts.length,1);
assert.equal(actions.filter(a=>a==='babysit_submitted').length,submissions);
await emit('prompt.submit',{text:'Continue working on the current goal.',origin:{kind:'composer'}});
await emit('prompt.submit',{text:'Continue working on the current goal.',origin:{kind:'plugin',name:'another'}});
await turn();
beforeCaptureReturn = human;
await failure();
beforeCaptureReturn = undefined;
await tick();
assert.equal(store.size,0);
assert.equal(prompts.length,1);
await turn();
await failure('authentication_failed');
await failure('rate_limit',{agent_id:'child'});
assert.equal(store.size,0);

// Old releases stored raw details at v1. Migration must never replay them.
store.set('gent-babysitter/v1/'+session,{details:'private text'});
store.set('gent-babysitter/v1/'+randomUUID(),{details:'old private text'});
await reload();
await tick();
assert.equal(store.size,0);
assert.equal(prompts.length,1);
const beforeHuman = actions.length;
offline = true;
failDelete = true;
await human();
await emit('turn.start',{turnId:randomUUID()});
await emit('classic.UserPromptSubmit',{session_id:session,prompt:'Continue working on the current goal.'});
assert.equal(prompts.length,1);
assert.equal(actions.length,beforeHuman);

// Exercise the retained settings guard with Claude's module re-entry suppression.
offline = false;
failDelete = false;
skipOwnHooks = true;
for (const intervene of [() => queueRow('enqueue'), markGoal, () =>
  row({type:'user',message:{role:'user',content:'changed during queue'}})]) {
  row({type:'attachment',attachment:{type:'goal_status',met:false,condition:randomUUID()}});
  await turn();
  await failure();
  queuedInput = intervene;
  const previous = guards.length;
  await tick();
  assert.equal(guards.length,previous+1);
  assert.notEqual(guards.at(-1),0);
  assert.equal(prompts.length,1);
}
queuedInput = undefined;
loseResult = true;
row({type:'attachment',attachment:{type:'goal_status',met:false,condition:randomUUID()}});
await turn();
await failure();
const [[lostKey,lostRecord]] = store;
await tick();
assert.equal(guards.at(-1),0);
assert.equal(prompts.length,2);
assert.equal(actions.filter(a=>a==='babysit_submitted').length,submissions);
assert.notEqual((await requestBridge({guard_event:{hook_event_name:'UserPromptSubmit',
  session_id:session, prompt:prompts.at(-1).text}})).exitCode,0);
store.set(lostKey,lostRecord); // A restored plugin store cannot revive the claimed input.
await reload();
await tick();
assert.equal(prompts.length,2);

// Claude may publish the native error after its StopFailure and turn.complete
// hooks. A retry must use the original interval even though the file arrived late.
async function unflushed() {
  markGoal();
  const turnId = await turn();
  const timestamp = new Date().toISOString();
  await emit('classic.StopFailure',{session_id:session,transcript_path:transcript,error:'unknown',
    last_assistant_message:'API Error: 400 Invalid value in input[0].tools[0].type. Supported values include function.'});
  await emit('turn.complete',{turnId,reason:'error',isAborted:false});
  assert.equal(store.size,0);
  assert.equal(timers.length,1);
  row({type:'assistant',isApiErrorMessage:true,timestamp,message:{content:'private provider failure'}});
}
await unflushed();
await timers.shift()();
assert.equal([...store.values()][0].reason,'tool_schema');
await unflushed();
await human();
await timers.shift()();
assert.equal(store.size,0);
// The native sender cannot bind a bare "please continue" to a retained guard.
// A paid node with ordinary chat recovery enabled must still leave this lane idle.
await reload();
writeFileSync(transcript,'');
const priorPrompts = prompts.length;
const priorActions = actions.length;
const prompt_id = randomUUID();
await emit('prompt.submit',{text:'please continue',wait:false,origin:{kind:'composer'}});
await emit('classic.UserPromptSubmit',{session_id:session,prompt_id,prompt:'please continue'});
row({type:'user',promptId:prompt_id,origin:{kind:'human'},message:{role:'user',content:'please continue'}});
const ordinaryTurn = randomUUID();
await emit('turn.start',{turnId:ordinaryTurn,text:'please continue'});
await failure('rate_limit',{prompt_id});
await emit('turn.complete',{turnId:ordinaryTurn,reason:'error',isAborted:false});
while (timers.length) await timers.shift()();
await reload();
await tick();
assert.equal(store.size,0);
assert.equal(prompts.length,priorPrompts);
assert.ok(actions.slice(priorActions).includes('babysit_capture'));
assert.ok(!actions.slice(priorActions).some(action =>
  action === 'babysit_claim' || action.includes('chat_claim')));
const humanGuard = await requestBridge({guard_event:{
  hook_event_name:'UserPromptSubmit',session_id:session,prompt:'please continue'}});
assert.equal(humanGuard.exitCode,0);
assert.equal(JSON.parse(humanGuard.stdout).continue,true);

responses.return(); // reading stdin must not keep the synthetic host alive
process.stdin.unref();
