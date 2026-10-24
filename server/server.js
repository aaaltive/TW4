// TI4 table server: serves TI4.html and proxies Claude calls so the API key never reaches a browser.
// No dependencies. Needs Node 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY = process.env.ANTHROPIC_API_KEY || '';
const OR_KEY = process.env.OPENROUTER_API_KEY || '';
const OR_PAID = (process.env.OPENROUTER_MODELS || '').split(',').map(s => s.trim()).filter(Boolean); // extra non-free models you explicitly allow
const PASS = process.env.TABLE_PASSCODE || '';
const PORT = parseInt(process.env.PORT || '8080', 10);
const MODELS = (process.env.ALLOWED_MODELS || 'claude-sonnet-5-5,claude-haiku-5-5').split(',').map(s => s.trim()).filter(Boolean);
const MAX_TOKENS_CAP = parseInt(process.env.MAX_TOKENS_CAP || '3000', 10);
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || String(300 * 1024), 10);
const RATE_PER_MIN = parseInt(process.env.RATE_PER_MIN || '40', 10);
const PAGE = process.env.PAGE_FILE || path.join(__dirname, '..', 'TI4.html');

if ((!KEY && !OR_KEY) || !PASS) { console.error('TABLE_PASSCODE and at least one of ANTHROPIC_API_KEY / OPENROUTER_API_KEY must be set.'); process.exit(1); }
// OpenRouter models look like "vendor/name". Any ":free" model is allowed (it cannot cost money); others only if listed in OPENROUTER_MODELS.
const isOR = m => typeof m === 'string' && m.includes('/');
const orOk = m => OR_KEY && isOR(m) && m.length < 120 && (m.endsWith(':free') || OR_PAID.includes(m));

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const passOk = given => crypto.timingSafeEqual(sha(given || ''), sha(PASS));

// per-IP sliding window for calls, plus a lockout after repeated wrong passcodes
const hits = new Map(), fails = new Map();
function limited(ip) {
  const now = Date.now(), arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(ip, arr);
  return arr.length > RATE_PER_MIN;
}
function locked(ip) { const f = fails.get(ip); return f && f.n >= 8 && Date.now() - f.t < 15 * 60000; }
function noteFail(ip) { const f = fails.get(ip) || { n: 0, t: 0 }; f.n++; f.t = Date.now(); fails.set(ip, f); }
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 60000)) hits.delete(k); for (const [k, v] of fails) if (now - v.t > 15 * 60000) fails.delete(k); }, 60000).unref();

function send(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(Object.assign(new Error('too big'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// OpenRouter speaks the OpenAI chat format; reply is reshaped to the Anthropic format the page already parses.
async function openrouter(res, model, messages, max_tokens) {
  const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 180000);
  try {
    const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST', signal: ctl.signal,
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + OR_KEY, 'x-title': 'TI4 table' },
      body: JSON.stringify({ model, max_tokens, messages })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j) return send(res, r.ok ? 502 : r.status, { error: 'upstream' });
    const text = (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '';
    send(res, 200, { content: [{ type: 'text', text }] });
  } catch (e) { send(res, 502, { error: 'upstream' }); } finally { clearTimeout(timer); }
}

async function claude(req, res, ip) {
  if (locked(ip)) return send(res, 429, { error: 'locked' });
  if (!passOk(req.headers['x-table-pass'])) { noteFail(ip); return send(res, 401, { error: 'bad passcode' }); }
  if (limited(ip)) return send(res, 429, { error: 'rate limited' });
  let b;
  try { b = JSON.parse(await readBody(req)); } catch (e) { return send(res, e.code === 413 ? 413 : 400, { error: 'bad body' }); }
  const msgs = Array.isArray(b.messages) ? b.messages : null;
  if (!msgs || !msgs.length || !msgs.every(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string'))
    return send(res, 400, { error: 'bad messages' });
  const max_tokens = Math.max(1, Math.min(parseInt(b.max_tokens, 10) || 2500, MAX_TOKENS_CAP));
  if (isOR(b.model)) {
    if (!orOk(b.model)) return send(res, 400, { error: 'model not allowed' });
    return openrouter(res, b.model, msgs, max_tokens);
  }
  if (!KEY) return send(res, 400, { error: 'anthropic not configured' });
  const model = MODELS.includes(b.model) ? b.model : MODELS[0];
  const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 120000);
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', signal: ctl.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model, max_tokens, messages: msgs })
    });
    const text = await r.text();
    res.writeHead(r.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(text);
  } catch (e) { send(res, 502, { error: 'upstream' }); } finally { clearTimeout(timer); }
}

http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || '';
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'GET' && url === '/api/health') return send(res, 200, { ok: true, proxy: true, anthropic: !!KEY, openrouter: !!OR_KEY });
  if (req.method === 'POST' && url === '/api/claude') return claude(req, res, ip);
  if (req.method === 'GET' && (url === '/' || url === '/index.html' || url === '/TI4.html')) {
    return fs.readFile(PAGE, (err, data) => {
      if (err) return send(res, 500, { error: 'page missing' });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' });
      res.end(data);
    });
  }
  send(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log('TI4 table listening on ' + PORT));
