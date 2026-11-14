// YHOD — Your Health, Our Duty.
// The whole application as one request handler: it serves the site and the API. No framework.
//   On a server of its own:  node server.js   (opens a port; needs GEMINI_API_KEY in the environment or in .env)
//   On Vercel:               api/index.js imports the handler from here; no port is opened (see vercel.json)
import fs from 'node:fs';
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { config } from './src/config.js';
import { db, dbDriver, dbReady } from './src/db.js';
import { initDataKey, dataKeySource } from './src/security.js';
import { Router, HttpError, securityHeaders, sendJson, sendBuffer, readJson, serveStatic, assetsId, clientIp, isSecureRequest } from './src/httpx.js';
import { hit, tidyUsage } from './src/ratelimit.js';
import { GeminiError, checkGemini, geminiState } from './src/gemini.js';
import { registerAuthRoutes, resolveSession, sessionCarriers, markOpened } from './src/routes-auth.js';
import { registerCheckinRoutes } from './src/routes-checkin.js';
import { registerCareRoutes } from './src/routes-care.js';
import { registerVoiceRoutes } from './src/routes-voice.js';
import { emergencyNumbers } from './shared/safety.js';
import { nowIso } from './src/db.js';

const router = new Router();

// Live status: is the server really connected to Gemini? (Lists models only — uses no generation quota.)
router.add('GET', '/api/status', {}, async (ctx) => {
  const gemini = await checkGemini(ctx.query.get('refresh') === '1' && hit(`status:${ctx.ip}`, 6, 60_000).ok);
  return {
    app: 'YHOD',
    time: nowIso(),
    database: dbDriver,
    // Where the records are kept, and whether they outlive this process. "durable: false" means a serverless
    // function without a database: whatever is saved is lost when the function instance goes away.
    storage: { kind: db.kind, durable: db.durable, key: dataKeySource() },
    platform: config.platform,
    files: assetsId(), // the fingerprint of the site's files; a page compares it with the one it was built from
    gemini,
    limits: { imageMB: Math.round(config.limits.maxImageBytes / 1048576), textPerDay: config.limits.textPerDay, imagePerDay: config.limits.imagePerDay, voicePerDay: config.limits.voicePerDay },
    emergencyNumbers: emergencyNumbers(ctx.query.get('tz') || ''),
  };
});

registerAuthRoutes(router);
registerCheckinRoutes(router);
registerCareRoutes(router);
registerVoiceRoutes(router);

const DEFAULT_BODY_LIMIT = 256 * 1024;

function errorBody(e) {
  if (e instanceof GeminiError) {
    return { status: e.httpStatus, body: { error: { code: e.code, message: e.message, detail: e.detail, retryAfterSec: e.retryAfterSec, source: 'gemini', attempts: e.attempts.map((a) => ({ model: a.model, status: a.status, code: a.code, message: a.message })) }, ...(e.extra || {}) } };
  }
  if (e instanceof HttpError) return { status: e.status, body: { error: { code: e.code, message: e.message, ...(e.extra || {}) } } };
  return null;
}

// Once per host name that requests are addressed to: which header NAMES arrive (never their values). A gateway in
// front of YHOD (a hosted preview, a reverse proxy) may add or remove headers, and that is invisible otherwise.
const hostsNoted = new Set();
function noteGateway(req) {
  const host = String(req.headers.host || '').toLowerCase().replace(/[^a-z0-9.:\-\[\]]/g, '').slice(0, 100);
  if (!host || hostsNoted.has(host) || hostsNoted.size >= 6) return;
  hostsNoted.add(host);
  console.log(`  first API request addressed to "${host}" arrived with these headers (names only): ${Object.keys(req.headers).sort().join(', ')}`);
}

// Did a request pass through a gateway (a hosted preview, a CDN, a reverse proxy)? Told by header names only.
const throughGateway = (req) => ['cf-ray', 'cdn-loop', 'via', 'forwarded', 'x-forwarded-for', 'x-forwarded-host'].some((name) => req.headers[name]);

async function handle(req, res) {
  const started = Date.now();
  const secure = isSecureRequest(req);
  const headers = securityHeaders(secure, { api: req.url.startsWith('/api/') });
  let url;
  try { url = new URL(req.url, 'http://yhod.local'); } catch { return sendJson(res, 400, { error: { code: 'BAD_URL', message: 'Bad request.' } }, headers); }
  const pathname = url.pathname;
  let routeName = pathname.startsWith('/api/') ? '/api/(unknown)' : '(static)';
  let sessionNote = '';
  let pageNote = '';
  const log = (status) => {
    // Access log: method, route pattern, status, time, how the session arrived, and whether the page is outdated.
    // Never bodies, query strings or header values.
    if (pathname.startsWith('/api/')) console.log(`${new Date().toISOString()} ${req.method} ${routeName} ${status} ${Date.now() - started}ms${sessionNote}${pageNote}`);
  };

  try {
    if (!pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } }, headers);
      const note = serveStatic(req, res, pathname, headers);
      if (note === false) return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Not found.' } }, headers);
      // Worth a line: the page itself, and files asked for under an address the current page does not use.
      if (note) console.log(`${new Date().toISOString()} ${req.method} ${pathname.slice(0, 80)} · ${note}${req.headers['if-none-match'] || req.headers['if-modified-since'] ? ' · the asker holds a stored copy' : ''}${throughGateway(req) ? ' · through the gateway' : ''}`);
      return;
    }

    // Everything below may read or write saved data: make sure the database is open and the key is loaded.
    try {
      await prepare();
    } catch (e) {
      console.error(`${new Date().toISOString()} DATABASE NOT AVAILABLE: ${e?.message || e}`);
      throw new HttpError(503, 'DATABASE_UNAVAILABLE', 'YHOD cannot reach its database at the moment. Nothing was changed. Please try again in a minute.', { retryAfterSec: 20 });
    }
    if (config.serverless && Date.now() - tidiedAt > 6 * 3600_000) await tidy();

    const ip = clientIp(req);
    noteGateway(req);
    const found = router.find(req.method, pathname);
    if (!found) throw new HttpError(404, 'NOT_FOUND', 'That address does not exist.');
    if (found.badPath) throw new HttpError(400, 'BAD_URL', 'Bad request.');
    if (found.methodNotAllowed) throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed.');
    const { route, params } = found;
    routeName = route.pattern;

    const window = hit(`api:${ip}`, config.limits.apiPerMinute, 60_000);
    if (!window.ok) throw new HttpError(429, 'RATE_LIMITED', 'Too many requests. Please slow down and try again shortly.', { retryAfterSec: window.retryAfterSec });

    // Cross-site request protection: browsers label where a request comes from.
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin' && site !== 'none') throw new HttpError(403, 'CROSS_SITE_BLOCKED', 'Cross-site requests are not allowed.');
    const unsafe = req.method !== 'GET' && req.method !== 'HEAD';
    if (unsafe) {
      // "Sec-Fetch-Site: same-origin" is the browser's own statement that the page and this address share one origin.
      // Page scripts cannot set or change it, and it stays true behind a gateway that rewrites the Host header
      // (a hosted preview, a reverse proxy). Only when a browser does not send it is the Origin header compared
      // with the host names this request was addressed to.
      if (site !== 'same-origin') {
        const origin = req.headers.origin;
        if (origin) {
          let host = '';
          try { host = new URL(origin).host; } catch { host = ''; }
          const addressedTo = [req.headers.host, ...String(req.headers['x-forwarded-host'] || '').split(',')].map((v) => String(v || '').trim().toLowerCase()).filter(Boolean);
          if (!host || (addressedTo.length && !addressedTo.includes(host.toLowerCase()))) throw new HttpError(403, 'CROSS_SITE_BLOCKED', 'Cross-site requests are not allowed.');
        }
      }
      // Every change must also carry the app's own header. Another website cannot add it: a custom header makes
      // the browser ask this server for permission first, and this server never grants it.
      if (req.headers['x-yhod'] !== '1') throw new HttpError(403, 'MISSING_HEADER', 'This request did not come from the YHOD app.');
    }

    // Which code is the browser running? Every page of the current site says which fingerprint it was built from.
    //   a fingerprint            → a page whose scripts all came from fingerprinted addresses, so they belong
    //                              together. If it is not the current fingerprint, the page was loaded before the
    //                              latest change: it works, and renews itself the next time it is loaded. Someone
    //                              who is using YHOD is never interrupted by an update.
    //   no "X-YHOD-Build" at all → code from before fingerprints existed. Where cookies do not get through (a hosted
    //                              preview), that code cannot stay signed in: YHOD would open and close again a
    //                              moment later.
    //   "plain"                  → an old copy of the page that reached at least one current script under its plain
    //                              address: old and new scripts may be mixed in it.
    // The last two are not let in. They are told to reload, and the browser is asked to drop its stored copies.
    // Requests that do not come from a browser page (scripts, tests) send no Sec-Fetch-Site and are left alone.
    const sentBuild = String(req.headers['x-yhod-build'] || '');
    const build = /^[A-Za-z0-9]{1,24}$/.test(sentBuild) ? sentBuild : '';
    const oldCode = (!!req.headers['sec-fetch-site'] && !build) || build === 'plain';
    const signIn = /^\/api\/auth\/(enter|signup|login)$/.test(pathname);
    if (signIn && throughGateway(req)) pageNote = ' · through the gateway';
    if (oldCode) pageNote += build === 'plain' ? ' · OLD PAGE (old copy of the page with current scripts mixed in)' : ' · OLD PAGE (code from before fingerprints)';
    else if (build && build !== assetsId()) pageNote += ` · page built from ${build}`;
    // Ask the browser to drop its stored copies of this site's files (nothing else), so that its next load is the
    // current site. Only where a page starts up or signs in, not on every request.
    if (oldCode && (signIn || pathname === '/api/status')) headers['Clear-Site-Data'] = '"cache"';
    if (oldCode && signIn) {
      // A plain 400 with its own code: old pages show the message of any error they do not know by name.
      throw new HttpError(400, 'OUTDATED_PAGE', 'YHOD has been updated since this page was loaded. Please reload the page, then enter your details again.');
    }

    const session = await resolveSession(req);
    // "session via header" = signed in through the app's own header; "no session (received: none)" = no cookie, header
    // or bearer arrived at all, which points at the browser or a gateway in between rather than at an expired session.
    sessionNote = session ? ` · session via ${session.via}` : route.opts.auth ? ` · no session (received: ${sessionCarriers(req)})` : '';
    if (route.opts.auth && !session) throw new HttpError(401, 'NOT_SIGNED_IN', 'Please log in to continue.');
    if (session) await markOpened(session.user);

    const cookies = [];
    const ctx = {
      req, res, params, ip, secure, headers,
      query: url.searchParams,
      embedded: req.headers['x-yhod-embedded'] === '1',
      user: session?.user || null,
      sessionId: session?.sessionId || null,
      sessionVia: session?.via || null,
      body: {},
      setCookie: (c) => cookies.push(c),
      sendBinary: (buf, type, extra = {}) => sendBuffer(res, 200, buf, type, { ...headers, ...extra }),
    };
    if (unsafe) ctx.body = await readJson(req, route.opts.bodyLimit || DEFAULT_BODY_LIMIT);

    const result = await route.handler(ctx);
    if (!res.headersSent) {
      const extra = { ...headers };
      if (cookies.length) extra['Set-Cookie'] = cookies;
      sendJson(res, 200, result ?? { ok: true }, extra);
    }
    log(res.statusCode);
  } catch (e) {
    const known = errorBody(e);
    if (known) {
      const extra = { ...headers };
      const retry = known.body.error.retryAfterSec;
      if (retry) extra['Retry-After'] = String(retry);
      sendJson(res, known.status, known.body, extra);
      log(known.status);
      if (e instanceof GeminiError) console.warn(`  Gemini: ${e.code} — ${String(e.detail || e.message).split('\n').join(' | ').slice(0, 600)}`);
      return;
    }
    // Unexpected error: log the technical details (never request bodies), tell the visitor plainly.
    console.error(`${new Date().toISOString()} ERROR ${req.method} ${routeName}:`, e?.stack || e);
    sendJson(res, 500, { error: { code: 'SERVER_ERROR', message: 'Something went wrong on the YHOD server. Your information is safe — please try again.' } }, headers);
    log(500);
  }
}

// ── start-up work that needs waiting for: the database and the key that protects the saved records ──
// Done once per process, the first time it is needed. If it fails (the database cannot be reached), the next
// request tries again.
let preparing = null;
function prepare() {
  preparing ||= (async () => {
    await dbReady();
    await initDataKey();
  })().catch((e) => { preparing = null; throw e; });
  return preparing;
}

// Small clean-ups: sessions that have run out, counters that no longer matter. A server does this every hour;
// a serverless function, which has no clock of its own, does it now and then on a request.
let tidiedAt = Date.now();
async function tidy() {
  tidiedAt = Date.now();
  try {
    await db.run('DELETE FROM sessions WHERE expires_at <= ?', nowIso());
    await tidyUsage();
  } catch { /* housekeeping only */ }
}

/**
 * Answer one request. This is the whole of YHOD: the pages, their files and the API.
 *   on a server of its own   node:http calls it for every request (see the end of this file)
 *   on Vercel                api/index.js exports it as the serverless function
 */
export async function yhod(req, res) {
  try {
    await handle(req, res);
  } catch (e) {
    console.error('Unhandled request error:', e?.stack || e);
    try { sendJson(res, 500, { error: { code: 'SERVER_ERROR', message: 'Something went wrong on the YHOD server.' } }); } catch { /* connection already closed */ }
  }
}
export default yhod;
export { geminiState };

// ── a server of its own: only when this file is started directly (node server.js) ──
// When the file is imported instead (by api/index.js on Vercel), nothing below runs: no port is opened and no
// timer is started, because a serverless function is called once per request and may be frozen in between.
const startedDirectly = (() => {
  try { return !!process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href; } catch { return false; }
})();

if (startedDirectly) {
  const server = http.createServer(yhod);
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;
  server.keepAliveTimeout = 65_000;

  process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e?.stack || e));
  process.on('uncaughtException', (e) => console.error('Uncaught exception:', e?.stack || e));

  setInterval(tidy, 3600_000).unref();

  const shutdown = () => {
    server.close(() => { db.close(); process.exit(0); });
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  try {
    await prepare();
  } catch (e) {
    console.error(`\nYHOD cannot start: ${e?.message || e}\n`);
    process.exit(1);
  }

  server.listen(config.port, config.host, async () => {
    console.log(`YHOD is running on http://${config.host}:${config.port}  (database: ${dbDriver})`);
    if (!config.gemini.apiKey) {
      console.warn('WARNING: GEMINI_API_KEY is not set. AI features will show a clear error until it is configured.');
      return;
    }
    const g = await checkGemini(true);
    if (g.ok) console.log(`Gemini connected. daily-analysis=${g.models.analysis} assessment=${g.models.assessment} vision=${g.models.vision} conversation=${g.models.conversation} voice=${g.models.voice} (${g.models.voiceName})`);
    else console.warn(`WARNING: Gemini check failed: ${g.error?.message || 'unknown error'}`);
  });
}
