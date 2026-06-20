import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import fs from 'fs';
import path from 'path';
import http from 'http';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKEN_FILE = path.join(__dirname, '.slack-token');
const USER_ID_FILE = path.join(__dirname, '.slack-user-id');
const CACERT_PATH = path.join(__dirname, 'certs', 'cacert.pem');
const TSACERT_PATH = path.join(__dirname, 'certs', 'tsa.crt');

const INSTALLATIONS_DIR = path.join(__dirname, 'installations');

// Find the user token + user id from the installation store (installations/{team}/)
function getUserCredentials() {
  if (!fs.existsSync(INSTALLATIONS_DIR)) return { token: null, userId: null };
  const teamDirs = fs.readdirSync(INSTALLATIONS_DIR);
  for (const team of teamDirs) {
    const teamPath = path.join(INSTALLATIONS_DIR, team);
    if (!fs.statSync(teamPath).isDirectory()) continue;
    const files = fs.readdirSync(teamPath);
    const userFile = files.find(f => f.startsWith('user-') && f.endsWith('-latest'));
    if (userFile) {
      const data = JSON.parse(fs.readFileSync(path.join(teamPath, userFile), 'utf8'));
      if (data.user?.token) return { token: data.user.token, userId: data.user.id || null };
    }
  }
  return { token: null, userId: null };
}

// Get credentials: try stored files first, then installation store
function getCredentials() {
  if (fs.existsSync(TOKEN_FILE)) {
    const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    const userId = fs.existsSync(USER_ID_FILE) ? fs.readFileSync(USER_ID_FILE, 'utf8').trim() : null;
    return { token, userId };
  }
  return getUserCredentials();
}

let { token, userId } = getCredentials();

// OAuth config
const CLIENT_ID = process.env.SLACK_CLIENT_ID;
const CLIENT_SECRET = process.env.SLACK_CLIENT_SECRET;
const USER_SCOPES = 'chat:write,canvases:write,channels:history,groups:history,im:history,mpim:history,search:read,users:read,users:read.email';
const PORT = process.env.MCP_PORT || 8080;
const REDIRECT_URI = `http://localhost:${PORT}/oauth/callback`;

// OAuth: exchange code for token
async function exchangeCodeForToken(code) {
  const res = await fetch('https://slack.com/api/oauth.v2.access', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code, redirect_uri: REDIRECT_URI }),
  });
  return res.json();
}

// --- FreeTSA RFC 3161 Timestamping ---

function stableStringify(obj) {
  if (obj === undefined) return undefined;
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(v => stableStringify(v) ?? 'null').join(',') + ']';
  return '{' + Object.keys(obj).filter(k => obj[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

function derLength(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  for (let l = len; l > 0; l >>= 8) bytes.unshift(l & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derSequence(parts) {
  const content = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([0x30]), derLength(content.length), content]);
}

function derInteger(n) {
  return Buffer.from([0x02, 0x01, n]);
}

function derBoolean(b) {
  return Buffer.from([0x01, 0x01, b ? 0xff : 0x00]);
}

// RFC 3161 TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint MessageImprint, certReq BOOLEAN }
function buildTSARequest(dataHash) {
  const algorithm = Buffer.from([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00]);
  const digest = Buffer.concat([Buffer.from([0x04]), derLength(dataHash.length), dataHash]);
  const messageImprint = derSequence([algorithm, digest]);
  return derSequence([derInteger(1), messageImprint, derBoolean(true)]);
}

async function timestampData(data) {
  const buffer = Buffer.from(data, 'utf-8');
  const hash = crypto.createHash('sha512').update(buffer).digest();
  const tsaRequest = buildTSARequest(hash);

  const res = await fetch('https://freetsa.org/tsr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: tsaRequest,
  });

  if (!res.ok) throw new Error(`FreeTSA responded with status ${res.status}`);
  const tsr = Buffer.from(await res.arrayBuffer());
  return { tsr, tsq: tsaRequest, hash: hash.toString('hex'), success: true, message: 'Timestamp received from FreeTSA' };
}

// Verifies a TSR token against its original request using openssl ts -verify.
function verifyTimestamp(tsqPath, tsrPath) {
  try {
    const output = execFileSync('openssl', [
      'ts', '-verify',
      '-in', tsrPath,
      '-queryfile', tsqPath,
      '-CAfile', CACERT_PATH,
      '-untrusted', TSACERT_PATH,
    ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, OPENSSL_CONF: 'NUL' } });
    return { verified: true, output: output.trim() };
  } catch (err) {
    const output = [err.stdout, err.stderr].filter(Boolean).join('').trim();
    return { verified: false, output: output || err.message };
  }
}

async function timestampFile(filePath, metadata = {}) {
  const fileData = fs.readFileSync(filePath, 'utf-8');
  const envelope = {
    data: fileData,
    req_param: metadata.req_param || null,
    retrieved_at: metadata.retrieved_at || new Date().toISOString(),
    source_of_data: metadata.source_of_data || 'File timestamped via MCP server',
    tool_calls: metadata.tool_calls || []
  };

  const envelopeJson = stableStringify(envelope);
  const result = await timestampData(envelopeJson);

  const envelopePath = `${filePath}.envelope.json`;
  const tsrPath = `${filePath}.tsr`;
  const hashPath = `${filePath}.sha512`;

  fs.writeFileSync(envelopePath, envelopeJson, 'utf-8');
  fs.writeFileSync(tsrPath, result.tsr);
  fs.writeFileSync(hashPath, result.hash, 'utf-8');

  return { envelope, envelopePath, tsrPath, hashPath, hash: result.hash, success: true };
}

function decodeTSR(tsr) {
  const hex = (Buffer.isBuffer(tsr) ? tsr : fs.readFileSync(tsr)).toString('hex');
  return `TSR Token (${hex.length / 2} bytes):\n  Hex: ${hex.substring(0, 80)}...\n\nVerify with: openssl ts -reply -in <file.tsr> -inform DER -text -noout`;
}

// --- End FreeTSA ---

function getSelfHash() {
  const src = fs.readFileSync(path.join(__dirname, 'mcp-server.js'));
  return crypto.createHash('sha256').update(src).digest('hex');
}

async function slackApi(method, body = {}, { callDir } = {}) {
  const requestBody = new URLSearchParams(
    Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)]))
  );
  const url = `https://slack.com/api/${method}`;
  const requestHeaders = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' };

  const res = await fetch(url, { method: 'POST', headers: requestHeaders, body: requestBody });

  const responseHeaders = Object.fromEntries(res.headers.entries());
  const rawBody = await res.text();
  const jsonBody = JSON.parse(rawBody);

  // Build wire artifact for timestamping
  const artifact = {
    request: { method: 'POST', url, headers: Object.fromEntries(Object.entries(requestHeaders).filter(([k]) => k.toLowerCase() !== 'authorization')), body },
    response: { status: res.status, headers: responseHeaders, body: rawBody },
    mcp_server_sha256: getSelfHash(),
    captured_at: new Date().toISOString(),
  };

  // Timestamp the artifact
  const artifactJson = stableStringify(artifact);
  let timestamp;
  try {
    const result = await timestampData(artifactJson);
    const tsDir = callDir || path.join(__dirname, 'timestamps', userId || 'unknown', String(Date.now()));
    if (!fs.existsSync(tsDir)) fs.mkdirSync(tsDir, { recursive: true });
    const base = method.replace(/\./g, '-');
    const existing = fs.readdirSync(tsDir).filter(f => f.startsWith(base) && f.endsWith('.json')).length;
    const filename = existing ? `${base}-${existing}` : base;
    const tsqPath = path.join(tsDir, `${filename}.tsq`);
    const tsrPath = path.join(tsDir, `${filename}.tsr`);
    fs.writeFileSync(path.join(tsDir, `${filename}.json`), artifactJson);
    fs.writeFileSync(tsqPath, result.tsq);
    fs.writeFileSync(tsrPath, result.tsr);

    const { verified, output } = verifyTimestamp(tsqPath, tsrPath);
    const relDir = path.relative(__dirname, tsDir).replace(/\\/g, '/');
    timestamp = {
      success: true,
      hash: result.hash,
      tsr_bytes: result.tsr.length,
      tsr_base64: result.tsr.toString('base64'),
      verified,
      verify_output: output,
      tsq_file: tsqPath,
      tsr_file: tsrPath,
      dir: tsDir,
      verification_instructions: `To independently verify this data, download the following files:\n` +
        `1. http://localhost:${PORT}/${relDir}/${filename}.json\n` +
        `2. http://localhost:${PORT}/${relDir}/${filename}.tsr\n` +
        `3. http://localhost:${PORT}/${relDir}/${filename}.tsq\n` +
        `4. http://localhost:${PORT}/certs/cacert.pem\n` +
        `5. http://localhost:${PORT}/certs/tsa.crt\n\n` +
        `Then run: openssl ts -verify -in ${filename}.tsr -queryfile ${filename}.tsq -CAfile cacert.pem -untrusted tsa.crt\n` +
        `To confirm the .json file matches the hash: openssl dgst -sha512 ${filename}.json`,
    };
  } catch (err) {
    console.error('Timestamp failed:', err.message);
    timestamp = { success: false, error: err.message };
  }

  return { data: jsonBody, timestamp, artifact };
}

// In-memory job store for non-blocking full-history fetches. Module-scope so it
// survives across requests even though createServer() spins up a fresh
// McpServer/transport per HTTP call.
const jobs = new Map();

const TEMPLATES_DIR = path.join(__dirname, 'templates');
const MESSAGE_TEMPLATE = fs.readFileSync(path.join(TEMPLATES_DIR, 'message.md'), 'utf-8');
const HISTORY_HEADER_TEMPLATE = fs.readFileSync(path.join(TEMPLATES_DIR, 'history-header.md'), 'utf-8');
const HISTORY_FOOTER_TEMPLATE = fs.readFileSync(path.join(TEMPLATES_DIR, 'history-footer.md'), 'utf-8');

function renderTemplate(template, vars) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? '');
}

const userNameCache = new Map();

async function resolveUserName(userId) {
  if (userNameCache.has(userId)) return userNameCache.get(userId);
  try {
    const { data } = await slackApi('users.info', { user: userId });
    const name = data.user?.real_name || data.user?.name || userId;
    userNameCache.set(userId, name);
    return name;
  } catch { userNameCache.set(userId, userId); return userId; }
}

function formatTs(ts) {
  if (!ts) return '';
  return new Date(parseFloat(ts) * 1000).toLocaleString('en-SG', { timeZone: 'Asia/Singapore', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) + ' SGT';
}

async function messagesToMarkdown(messages, channel) {
  const userIds = [...new Set(messages.map(m => m.user).filter(Boolean))];
  await Promise.all(userIds.map(resolveUserName));
  return messages
    .map(m => renderTemplate(MESSAGE_TEMPLATE, {
      user: userNameCache.get(m.user) || m.user,
      ts: formatTs(m.ts),
      text: (m.text || '').replace(/\n/g, ' '),
      channel: channel || '',
      thread_ts: formatTs(m.thread_ts),
      subtype: m.subtype || '',
      edited: m.edited ? 'true' : '',
      reactions: (m.reactions || []).map(r => `:${r.name}:×${r.count}`).join(' ') || '',
      files: (m.files || []).length ? `${m.files.length} file(s)` : '',
      reply_count: m.reply_count != null ? String(m.reply_count) : '',
      team: m.team || '',
    }))
    .join('\n');
}

function historyHeader(count, pages, { channel, duration } = {}) {
  return renderTemplate(HISTORY_HEADER_TEMPLATE, { count, pages, channel: channel || '', duration: duration || '', sha256: getSelfHash() });
}

function historyFooter(count, pages, { channel, timestamp_links, duration, has_more } = {}) {
  return renderTemplate(HISTORY_FOOTER_TEMPLATE, { count, pages, channel: channel || '', timestamp_links: timestamp_links || '', duration: duration || '', has_more: has_more ? 'true' : '', sha256: getSelfHash() });
}

function runFullHistoryJob(jobId, channel, pageSize) {
  const job = jobs.get(jobId);
  (async () => {
    let cursor;
    try {
      do {
        const { data, timestamp } = await slackApi('conversations.history', { channel, limit: pageSize, cursor }, { callDir: job.callDir });
        if (data.error) throw new Error(data.error);
        job.messages.push(...(data.messages || []).map(m => ({ user: m.user, text: m.text, ts: m.ts, thread_ts: m.thread_ts, subtype: m.subtype, edited: m.edited, reactions: m.reactions, files: m.files, reply_count: m.reply_count, team: m.team })));
        job.timestamps.push(timestamp);
        job.pages_fetched++;
        cursor = data.has_more ? data.response_metadata?.next_cursor : undefined;
      } while (cursor);
      job.status = 'done';
    } catch (err) {
      job.status = 'error';
      job.error = err.message;
    }
    job.finished_at = new Date().toISOString();
  })();
}

function makeCallDir() {
  const dir = path.join(__dirname, 'timestamps', userId || 'unknown', String(Date.now()));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function createServer() {
  const server = new McpServer({ name: 'slack-local', version: '1.0.0' });

  server.tool('send_message', 'Send a message to a Slack channel', {
    channel: z.string().describe('Channel ID or name (e.g. C12345 or #general)'),
    text: z.string().describe('Message text'),
  }, async ({ channel, text }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('chat.postMessage', { channel, text }, { callDir });
    return { content: [{ type: 'text', text: JSON.stringify({ data, timestamp }, null, 2) }] };
  });

  server.tool('list_channels', 'List public Slack channels', {
    limit: z.number().optional().default(100).describe('Max channels to return'),
  }, async ({ limit }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('conversations.list', { types: 'public_channel', limit }, { callDir });
    return { content: [{ type: 'text', text: JSON.stringify({ data: data.channels?.map(c => ({ id: c.id, name: c.name })) || data, timestamp }, null, 2) }] };
  });

  server.tool('read_messages', 'Read recent messages from a channel', {
    channel: z.string().describe('Channel ID'),
    limit: z.number().optional().default(100).describe('Number of messages'),
  }, async ({ channel, limit }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('conversations.history', { channel, limit }, { callDir });
    return { content: [{ type: 'text', text: JSON.stringify({ data: data.messages?.map(m => ({ user: m.user, text: m.text, ts: m.ts })) || data, timestamp }, null, 2) }] };
  });

  server.tool('get_full_history', 'Fetch the entire message history of a channel by paginating until exhausted, returning everything in one response as markdown', {
    channel: z.string().describe('Channel ID'),
    page_size: z.number().optional().default(1000).describe('Messages per page (Slack max: 1000)'),
  }, async ({ channel, page_size }) => {
    const callDir = makeCallDir();
    const messages = [];
    const timestamps = [];
    let cursor;
    const startTime = Date.now();
    do {
      const { data, timestamp } = await slackApi('conversations.history', { channel, limit: page_size, cursor }, { callDir });
      if (data.error) return { content: [{ type: 'text', text: JSON.stringify({ error: data.error, timestamp }, null, 2) }] };
      messages.push(...(data.messages || []).map(m => ({ user: m.user, text: m.text, ts: m.ts, thread_ts: m.thread_ts, subtype: m.subtype, edited: m.edited, reactions: m.reactions, files: m.files, reply_count: m.reply_count, team: m.team })));
      timestamps.push(timestamp);
      cursor = data.has_more ? data.response_metadata?.next_cursor : undefined;
    } while (cursor);
    const duration = `${((Date.now() - startTime) / 1000).toFixed(1)}s`;
    const timestamp_links = timestamps.filter(t => t.success).map(t => t.verification_instructions).join('\n');
    const md = `${historyHeader(messages.length, timestamps.length, { channel, duration })}\n\n${await messagesToMarkdown(messages, channel)}\n\n${historyFooter(messages.length, timestamps.length, { channel, timestamp_links, duration, has_more: false })}`;
    fs.writeFileSync(path.join(callDir, `history.md`), md);
    return { content: [{ type: 'text', text: md }] };
  });

  server.tool('start_full_history_fetch', 'Start a non-blocking background fetch of a channel\'s entire message history. Returns a job_id immediately; poll it with get_full_history_status', {
    channel: z.string().describe('Channel ID'),
    page_size: z.number().optional().default(1000).describe('Messages per page (Slack max: 1000)'),
  }, async ({ channel, page_size }) => {
    const jobId = crypto.randomUUID();
    const callDir = makeCallDir();
    jobs.set(jobId, { status: 'running', channel, callDir, messages: [], timestamps: [], pages_fetched: 0, error: null, started_at: new Date().toISOString(), finished_at: null });
    runFullHistoryJob(jobId, channel, page_size);
    return { content: [{ type: 'text', text: JSON.stringify({ job_id: jobId, status: 'started' }, null, 2) }] };
  });

  server.tool('get_full_history_status', 'Poll a background full-history fetch job. Returns progress while running, and full data once status is "done"', {
    job_id: z.string().describe('job_id returned by start_full_history_fetch'),
  }, async ({ job_id }) => {
    const job = jobs.get(job_id);
    if (!job) return { content: [{ type: 'text', text: JSON.stringify({ error: `no such job: ${job_id}` }, null, 2) }] };
    const summary = { status: job.status, channel: job.channel, pages_fetched: job.pages_fetched, message_count: job.messages.length, started_at: job.started_at, finished_at: job.finished_at, error: job.error };
    if (job.status !== 'done') return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
    summary.timestamps = job.timestamps;
    const duration = `${((new Date(job.finished_at) - new Date(job.started_at)) / 1000).toFixed(1)}s`;
    const header = `${JSON.stringify(summary, null, 2)}\n\n${historyHeader(job.messages.length, job.pages_fetched, { channel: job.channel, duration })}`;
    const md = `${header}\n\n${await messagesToMarkdown(job.messages, job.channel)}`;
    fs.writeFileSync(path.join(job.callDir, `history.md`), md);
    return { content: [{ type: 'text', text: md }] };
  });

  server.tool('reply_to_thread', 'Reply to a message thread', {
    channel: z.string().describe('Channel ID'),
    thread_ts: z.string().describe('Timestamp of parent message'),
    text: z.string().describe('Reply text'),
  }, async ({ channel, thread_ts, text }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('chat.postMessage', { channel, thread_ts, text }, { callDir });
    return { content: [{ type: 'text', text: JSON.stringify({ data, timestamp }, null, 2) }] };
  });

  server.tool('search_messages', 'Search Slack messages', {
    query: z.string().describe('Search query'),
  }, async ({ query }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('search.messages', { query }, { callDir });
    const matches = data.messages?.matches?.map(m => ({ channel: m.channel?.name, text: m.text, user: m.user, ts: m.ts }));
    return { content: [{ type: 'text', text: JSON.stringify({ data: matches || data, timestamp }, null, 2) }] };
  });

  server.tool('list_users', 'List workspace users', {}, async () => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('users.list', {}, { callDir });
    const users = data.members?.filter(u => !u.deleted && !u.is_bot).map(u => ({ id: u.id, name: u.real_name || u.name }));
    return { content: [{ type: 'text', text: JSON.stringify({ data: users || data, timestamp }, null, 2) }] };
  });

  server.tool('get_user_info', 'Get info about a user', {
    user: z.string().describe('User ID'),
  }, async ({ user }) => {
    const callDir = makeCallDir();
    const { data, timestamp } = await slackApi('users.info', { user }, { callDir });
    return { content: [{ type: 'text', text: JSON.stringify({ data: data.user || data, timestamp }, null, 2) }] };
  });

  return server;
}

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // OAuth: start flow
  if (url.pathname === '/oauth/install') {
    const state = crypto.randomBytes(16).toString('hex');
    const authUrl = `https://slack.com/oauth/v2/authorize?client_id=${CLIENT_ID}&user_scope=${USER_SCOPES}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
    res.writeHead(302, { Location: authUrl });
    res.end();
    return;
  }

  // OAuth: callback
  if (url.pathname === '/oauth/callback') {
    const code = url.searchParams.get('code');
    if (!code) {
      res.writeHead(400);
      res.end('Missing code parameter');
      return;
    }
    const data = await exchangeCodeForToken(code);
    if (data.authed_user?.access_token) {
      token = data.authed_user.access_token;
      userId = data.authed_user.id || null;
      fs.writeFileSync(TOKEN_FILE, token);
      if (userId) fs.writeFileSync(USER_ID_FILE, userId);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<h1>✅ Authenticated!</h1><p>Slack token saved. You can close this window.</p>');
      console.log('OAuth complete — token saved.');
    } else {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end(`<h1>❌ OAuth failed</h1><pre>${JSON.stringify(data, null, 2)}</pre>`);
    }
    return;
  }

  // MCP endpoint
  if (url.pathname === '/mcp') {
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `No token. Visit http://localhost:${PORT}/oauth/install to authenticate.` }));
      return;
    }

    if (req.method === 'POST') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());

      console.log(`Got req: ${JSON.stringify(body, null, 2)}`);

      const server = createServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      res.on('close', () => { transport.close(); server.close(); });
    } else {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
    }
    return;
  }

  // Serve timestamp files
  if (url.pathname.startsWith('/timestamps/')) {
    const filePath = path.join(__dirname, decodeURIComponent(url.pathname));
    if (fs.existsSync(filePath) && !fs.statSync(filePath).isDirectory()) {
      const ext = path.extname(filePath);
      const mime = { '.json': 'application/json', '.tsr': 'application/timestamp-reply', '.tsq': 'application/timestamp-query', '.pem': 'application/x-pem-file', '.crt': 'application/x-x509-ca-cert' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime, 'Content-Disposition': `attachment; filename="${path.basename(filePath)}"` });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
  }

  // Serve cert files for verification
  if (url.pathname.startsWith('/certs/')) {
    const filePath = path.join(__dirname, decodeURIComponent(url.pathname));
    if (fs.existsSync(filePath) && !fs.statSync(filePath).isDirectory()) {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${path.basename(filePath)}"` });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
  }

  res.writeHead(404);
  res.end('Not found');
});

httpServer.listen(PORT, () => {
  console.log(`Slack MCP server running at http://localhost:${PORT}/mcp`);
  if (!token) {
    console.log(`⚠️  No token found. Visit http://localhost:${PORT}/oauth/install to authenticate.`);
  }
});
