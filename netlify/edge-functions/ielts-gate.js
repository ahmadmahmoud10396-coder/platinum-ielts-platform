/**
 * IELTS Academic & General — fail-closed Netlify edge auth gateway.
 * Serves NO course content as a public static file.
 */
const ORIGIN = 'https://german-a1-student-portal-staging.up.railway.app';
const BASE = '/platforms/ielts-academic-general';
const COOKIE = 'pa_ielts_ag_session';
const ALLOWED_GET = new Set(['student', 'course', 'api/account', 'api/progress', 'mic-check']);
const ALLOWED_POST = new Set(['login', 'logout', 'api/progress']);
const REQUIRES_ACCOUNT = new Set(['course', 'api/progress', 'api/account', 'mic-check']);

const securityHeaders = {
  'Cache-Control': 'private, no-store, max-age=0',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
};
function response(body, status, extra={}) {
  return new Response(body, { status, headers: { ...securityHeaders, 'Content-Type': 'text/plain; charset=utf-8', ...extra }});
}
function redirect(origin) {
  return response('', 303, { Location: origin + BASE + '/student' });
}
function permittedCookie(request) {
  const pair = (request.headers.get('cookie') || '').split(';')
    .map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  return pair || '';
}
function correctOrigin(request, origin) {
  const fetchSite = request.headers.get('Sec-Fetch-Site');
  return request.headers.get('Origin') === origin && (!fetchSite || fetchSite === 'same-origin');
}
async function accountIsValid(cookie, fetchImpl) {
  if (!cookie) return false;
  try {
    const upstream = await fetchImpl(ORIGIN + BASE + '/api/account', {
      method: 'GET', redirect: 'manual',
      headers: { Cookie: cookie, Accept: 'application/json', 'Accept-Encoding': 'identity' }
    });
    if (upstream.status !== 200) return false;
    const account = await upstream.json();
    if (account.active !== true || !account.username) return false;
    if (account.expires_at && new Date(account.expires_at).getTime() <= Date.now()) return false;
    return true;
  } catch (_) { return false; }
}
async function getBody(request) {
  const declared = Number(request.headers.get('Content-Length') || '0');
  if (declared > 1024 * 1024) return null;
  const body = await request.arrayBuffer();
  return body.byteLength <= 1024 * 1024 ? body : null;
}

export async function handleIelts(request, fetchImpl = fetch) {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'POST')
    return response('Method not allowed', 405, { Allow: 'GET, HEAD, POST' });

  // Reject all direct course files and old public URL aliases.
  if (['/', '/index.html', '/ielts-academic-general', '/ielts-academic-general/'].includes(url.pathname)) {
    return method === 'POST' ? response('Not found', 404) : redirect(url.origin);
  }
  if (url.pathname === BASE) return method === 'POST' ? response('Not found', 404) : redirect(url.origin);
  if (!url.pathname.startsWith(BASE + '/')) return response('Not found', 404);
  const operation = url.pathname.slice(BASE.length + 1);
  if (operation.includes('/') && !operation.startsWith('api/')) return response('Not found', 404);
  if (method === 'POST' ? !ALLOWED_POST.has(operation) : !ALLOWED_GET.has(operation))
    return response('Not found', 404);
  if (method === 'POST' && !correctOrigin(request, url.origin)) return response('Forbidden', 403);

  const cookie = permittedCookie(request);
  if (REQUIRES_ACCOUNT.has(operation) && !(await accountIsValid(cookie, fetchImpl))) {
    return method === 'POST' || operation.startsWith('api/')
      ? response('{"error":"unauthorized"}', 401, { 'Content-Type': 'application/json; charset=utf-8' })
      : redirect(url.origin);
  }
  const headers = new Headers({ 'Accept-Encoding': 'identity' });
  for (const h of ['Accept', 'Accept-Language', 'Content-Type']) {
    const v = request.headers.get(h);
    if (v) headers.set(h, v);
  }
  if (cookie) headers.set('Cookie', cookie);
  let body;
  if (method === 'POST') {
    body = await getBody(request);
    if (body === null) return response('Request body too large', 413);
    headers.set('Origin', ORIGIN);
    headers.set('Referer', ORIGIN + BASE + '/student');
  }
  let upstream;
  try {
    const target = new URL(ORIGIN + BASE + '/' + operation);
    // Student identity comes exclusively from the server-validated HttpOnly cookie.
    upstream = await fetchImpl(target, { method, headers, body, redirect: 'manual' });
  } catch (_) { return response('Upstream unavailable', 502); }

  const resultHeaders = new Headers(upstream.headers);
  for (const [k, v] of Object.entries(securityHeaders)) resultHeaders.set(k, v);
  resultHeaders.delete('Access-Control-Allow-Origin');
  resultHeaders.delete('Content-Length');
  resultHeaders.delete('Content-Encoding');
  resultHeaders.delete('ETag');

  if (upstream.status >= 300 && upstream.status < 400) {
    const location = resultHeaders.get('Location');
    if (location) {
      let destination;
      try { destination = new URL(location, ORIGIN + BASE + '/' + operation); }
      catch (_) { return response('Bad upstream redirect', 502); }
      if (destination.origin !== ORIGIN || !destination.pathname.startsWith(BASE + '/'))
        return response('Bad upstream redirect', 502);
      resultHeaders.set('Location', url.origin + destination.pathname);
    }
  }

  const setCookies = upstream.headers.getSetCookie?.() ||
    (upstream.headers.get('Set-Cookie') ? [upstream.headers.get('Set-Cookie')] : []);
  resultHeaders.delete('Set-Cookie');
  for (const item of setCookies) {
    if (!item.startsWith(COOKIE + '=')) continue;
    const clean = item.replace(/;\s*Domain=[^;]*/gi, '');
    if (/;\s*Secure\b/i.test(clean) && /;\s*HttpOnly\b/i.test(clean) && /;\s*SameSite=Strict\b/i.test(clean))
      resultHeaders.append('Set-Cookie', clean);
  }
  return new Response(method === 'HEAD' ? null : upstream.body, {
    status: upstream.status, statusText: upstream.statusText, headers: resultHeaders
  });
}

// Netlify passes a Context object as argument 2; never treat it as fetch().
export default async function edgeHandler(request) { return handleIelts(request); }
export const config = { path: '/*' };
