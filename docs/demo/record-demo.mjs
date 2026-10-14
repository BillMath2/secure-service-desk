// Node 22+, authenticated OBS WebSocket v5, dedicated prepared demo scene.
// Run from the repository root: node docs/demo/record-demo.mjs [--test]
import {readFileSync, writeFileSync, existsSync} from 'node:fs';
import {createHash, randomUUID} from 'node:crypto';
import {join, resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const test = process.argv.includes('--test');
const root = process.cwd();
const slides = JSON.parse(readFileSync('docs/demo/storyboard.json', 'utf8'));
const audio = resolve('.lab/demo/narration-final.wav');
for (const file of [audio, ...slides.map(s => resolve(s.image))]) {
  if (!existsSync(file)) throw new Error(`Missing prepared asset: ${file}`);
}
const cfg = JSON.parse(readFileSync(join(process.env.APPDATA,
  'obs-studio/plugin_config/obs-websocket/config.json'), 'utf8').replace(/^\uFEFF/, ''));
if (!cfg.auth_required) throw new Error('Authenticated OBS control is required');
const hash = s => createHash('sha256').update(s).digest('base64');
const ws = new WebSocket(`ws://127.0.0.1:${cfg.server_port}`);
const pending = new Map();
let readyResolve, readyReject;
const ready = new Promise((resolve, reject) => {readyResolve = resolve; readyReject = reject;});
const connectTimer = setTimeout(() => readyReject(new Error('OBS connection timeout')), 15000);
ws.onmessage = event => {
  const m = JSON.parse(event.data);
  if (m.op === 0) {
    const d = {rpcVersion: 1, eventSubscriptions: 0};
    if (m.d.authentication) d.authentication = hash(hash(cfg.server_password +
      m.d.authentication.salt) + m.d.authentication.challenge);
    ws.send(JSON.stringify({op: 1, d}));
  }
  if (m.op === 2) {clearTimeout(connectTimer); readyResolve();}
  if (m.op === 7) {
    const p = pending.get(m.d.requestId);
    if (!p) return;
    clearTimeout(p.timer); pending.delete(m.d.requestId);
    if (m.d.requestStatus.result) p.resolve(m.d.responseData ?? {});
    else p.reject(new Error(`${m.d.requestType}: ${m.d.requestStatus.comment}`));
  }
};
ws.onerror = () => readyReject(new Error('OBS connection failed'));
function call(requestType, requestData = {}) {
  const requestId = randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {pending.delete(requestId); reject(new Error(`${requestType}: timeout`));}, 15000);
    pending.set(requestId, {resolve, reject, timer});
    ws.send(JSON.stringify({op: 6, d: {requestType, requestId, requestData}}));
  });
}
const media = action => call('TriggerMediaInputAction', {
  inputName: 'UK narration', mediaAction: `OBS_WEBSOCKET_MEDIA_INPUT_ACTION_${action}`});
const slide = s => call('SetInputSettings', {inputName: 'Evidence slide',
  inputSettings: {file: resolve(s.image)}, overlay: true});
let recording = false;
const evidence = {mode: test ? 'static-source-validation' : 'final-evidence-walkthrough',
  startedAt: new Date().toISOString(), voice: 'Microsoft Hazel / en-GB / female',
  scope: 'Saved executed evidence, synthetic identities; no live human interaction footage', transitions: []};
try {
  await ready;
  const profile = await call('GetProfileList');
  const collection = await call('GetSceneCollectionList');
  if (profile.currentProfileName !== 'Secure Service Desk' ||
      collection.currentSceneCollectionName !== 'Secure Service Desk') {
    throw new Error('Select the dedicated Secure Service Desk profile and collection first');
  }
  const status = await call('GetRecordStatus');
  if (status.outputActive) throw new Error('An existing OBS recording is active');
  const items = await call('GetSceneItemList', {sceneName: 'Evidence'});
  for (const item of items.sceneItems) await call('SetSceneItemEnabled', {
    sceneName: 'Evidence', sceneItemId: item.sceneItemId,
    sceneItemEnabled: ['Evidence slide', 'UK narration'].includes(item.sourceName)});
  await call('SetCurrentProgramScene', {sceneName: 'Evidence'});
  await call('SetRecordDirectory', {recordDirectory: resolve('.lab/demo')});
  await slide(slides[0]);
  await call('SetInputSettings', {inputName: 'UK narration', overlay: true,
    inputSettings: {local_file: audio, is_local_file: true, looping: false}});
  await media('STOP');
  await delay(500);
  evidence.videoSettings = await call('GetVideoSettings');
  evidence.statsBefore = await call('GetStats');
  await call('StartRecord'); recording = true;
  await media('RESTART');
  const start = performance.now();
  evidence.transitions.push({slide: 1, targetSeconds: 0, actualSeconds: 0});
  let elapsed = 0;
  for (let i = 0; i < (test ? 1 : slides.length); i++) {
    elapsed += test ? 20 : slides[i].duration;
    await delay(Math.max(0, start + elapsed * 1000 - performance.now()));
    if (!test && i + 1 < slides.length) {
      await slide(slides[i + 1]);
      evidence.transitions.push({slide: i + 2, targetSeconds: elapsed,
        actualSeconds: (performance.now() - start) / 1000});
    }
  }
  if (!test) await delay(1500);
  evidence.recording = await call('StopRecord'); recording = false;
  await media('STOP');
  evidence.statsAfter = await call('GetStats');
  evidence.finishedAt = new Date().toISOString();
  evidence.passed = true;
} catch (error) {
  evidence.passed = false; evidence.error = error.message; process.exitCode = 1;
} finally {
  if (recording) {try {evidence.emergencyStop = await call('StopRecord'); await media('STOP');} catch {}}
  clearTimeout(connectTimer);
  for (const p of pending.values()) clearTimeout(p.timer);
  ws.close();
  writeFileSync(resolve(`.lab/demo/${test ? 'static-test' : 'final'}-capture.json`),
    JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify(evidence));
}
