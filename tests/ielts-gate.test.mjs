import test from 'node:test';
import assert from 'node:assert/strict';
import edgeHandler, { handleIelts } from '../netlify/edge-functions/ielts-gate.js';
const here = 'https://platinum-ielts-academic-general-jo.netlify.app';
const base = '/platforms/ielts-academic-general';
const token = 'pa_ielts_ag_session=test-token';
const req = (path, opts={}) => new Request(here + path, opts);
const validAccount = { username: 'sample', active: true, expires_at: '2099-01-01T00:00:00Z' };
const remote = (account=validAccount) => async (url, opts) => {
  if (new URL(url).pathname.endsWith('/api/account'))
    return Response.json(account, { status: account ? 200 : 401 });
  return new Response('<!doctype html><title>COURSE</title>', { status: 200, headers: { 'content-type': 'text/html' }});
};

test('public direct file routes are blocked', async () => {
  for (const p of ['/index.html', '/', '/ielts-academic-general/']) {
    const r = await handleIelts(req(p), remote());
    assert.equal(r.status, 303);
    assert.ok(r.headers.get('Location').endsWith(base + '/student'));
  }
  for (const p of ['/private/index.html', '/.netlify/functions/ielts-gate', '/course'])
    assert.equal((await handleIelts(req(p), remote())).status, 404);
});
test('unauthenticated course request redirects without course HTML', async () => {
  const r = await handleIelts(req(base + '/course'), remote());
  assert.equal(r.status, 303);
  assert.ok(!(await r.text()).includes('COURSE'));
});
test('expired and deactivated sessions do not receive course content', async () => {
  for (const account of [null, { ...validAccount, active: false }, { ...validAccount, expires_at: '2020-01-01T00:00:00Z' }]) {
    const r = await handleIelts(req(base + '/course', { headers: { Cookie: token }}), remote(account));
    assert.equal(r.status, 303);
  }
});
test('verified active student receives private, no-store course response', async () => {
  const r = await handleIelts(req(base + '/course', { headers: { Cookie: token }}), remote());
  assert.equal(r.status, 200);
  assert.ok((await r.text()).includes('COURSE'));
  assert.equal(r.headers.get('Cache-Control'), 'private, no-store, max-age=0');
});
test('cross-origin POSTs and disallowed POST paths are rejected', async () => {
  assert.equal((await handleIelts(req(base + '/login', { method:'POST',headers:{Origin:'https://evil.test'}, body:'{}' }), remote())).status, 403);
  assert.equal((await handleIelts(req(base + '/course', { method:'POST',headers:{Origin:here}, body:'{}' }), remote())).status, 404);
});
test('same-origin login is forwarded only to existing academy backend', async () => {
  const password = 'test-only-password-not-a-real-credential';
  const r = await handleIelts(req(base+'/login', {method:'POST',headers:{Origin:here,'Content-Type':'application/json'},body:JSON.stringify({username:'sample',password})}), async (url, opts) => {
    assert.equal(new URL(url).origin,'https://german-a1-student-portal-staging.up.railway.app');
    assert.equal(opts.headers.get('Origin'),'https://german-a1-student-portal-staging.up.railway.app');
    assert.ok(new TextDecoder().decode(opts.body).includes(password));
    return new Response('{"ok":true}',{status:200,headers:{'content-type':'application/json'}});
  });
  assert.equal(r.status,200);
  assert.ok(!(await r.text()).includes(password));
});
test('progress API requires a valid account', async () => {
  assert.equal((await handleIelts(req(base+'/api/progress'), remote())).status,401);
});
test('Netlify context argument does not replace fetch', async () => {
  const r = await edgeHandler(req('/index.html'), { geo: { country: { code: 'JO' } } });
  assert.equal(r.status, 303);
});
