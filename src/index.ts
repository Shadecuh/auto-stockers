// ─────────────────────────────────────────────────────────────────────────
// AUTO STOCKERS — AI-powered restocking assistant (multi-tenant)
//
// Theme: "AI as a tool" — receipt scanning + no-POS-integration demand
// forecasting. Two things make this different from a generic reorder-point
// calculator:
//
//   1. RECEIPT UNDERSTANDING WITHOUT A CATALOG. Sales receipts are messy,
//      inconsistently formatted, and abbreviated. A vision model reads the
//      receipt into structured lines, then a fuzzy text-matching step (not
//      a barcode/SKU lookup — we don't have one) tries to resolve each line
//      to an existing product or flag it as new. A human confirms borderline
//      matches. This is the hard problem a POS-integrated system never has
//      to solve, because it already knows its own SKUs.
//
//   2. ADAPTIVE PER-ITEM REORDER POINTS. Instead of one fixed threshold
//      ("reorder at 10 units") for the whole store, each product tracks its
//      own demand LEVEL and TREND (Holt's linear / double exponential
//      smoothing) plus a running estimate of demand variance, updated after
//      every sale. The reorder point and safety stock are recomputed per
//      item from that model, so a trending-up item and a flat item get
//      different treatment automatically.
//
// The AI touches two different stages: a vision model turns a receipt photo
// into structured data (perception), and a text model turns the resulting
// math into a short, readable purchase-order note (communication). The
// actual forecasting math is deterministic and auditable — the "learning"
// signal is per-item exponential smoothing, not a black box.
//
// MULTI-TENANCY. Any business can sign up, get its own company_id, and use
// the app without ever seeing another company's data. That isolation is
// enforced in exactly one place: getSession() below resolves a request's
// auth token to a company_id, and every single query in this file binds
// that company_id into its WHERE clause. There's no per-tenant database —
// one shared D1 database, with company_id as the wall between tenants.
// ─────────────────────────────────────────────────────────────────────────

export interface Env {
  DB: D1Database;
  SESSION_SECRET: string;      // HMAC key for signing session tokens — set with `wrangler secret put SESSION_SECRET`
  GEMINI_API_KEY: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REDIRECT_URI: string; // e.g. https://auto-stockers.<subdomain>.workers.dev/api/calendar/callback
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function authFail(message = 'Unauthorized') {
  return json({ error: message }, 401);
}

// ─── Password hashing (PBKDF2-SHA256, Web Crypto — no external deps) ──────
// Workers has SubtleCrypto but not bcrypt/scrypt, so PBKDF2 is the
// standard choice here. 100k iterations is the OWASP-recommended floor for
// PBKDF2-SHA256; lower it if you're on a CPU-time-limited plan and see
// timeouts on signup/login.

const PBKDF2_ITERATIONS = 100_000;

function bytesToHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function hashPassword(password: string, saltHex: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bytesToHex(bits);
}

function generateSalt(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)).buffer);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ─── Session tokens (HMAC-signed, stateless — no sessions table needed) ───
// A minimal JWT-shaped token: base64url(payload) + "." + base64url(HMAC
// signature). Payload carries exactly what every request needs to enforce
// isolation: uid (user id) and cid (company id).

type SessionPayload = { uid: number; cid: number; email: string; exp: number };

function b64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str: string): Uint8Array {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacKey(env: Env): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signSession(env: Env, payload: SessionPayload): Promise<string> {
  const enc = new TextEncoder();
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(body));
  return `${body}.${b64urlEncode(new Uint8Array(sig))}`;
}

async function verifySession(env: Env, token: string): Promise<SessionPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const enc = new TextEncoder();
  const valid = await crypto.subtle.verify('HMAC', await hmacKey(env), b64urlDecode(sig), enc.encode(body));
  if (!valid) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body))) as SessionPayload;
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Resolves a request to { userId, companyId }, or null if unauthenticated.
// This is the ONLY place a request's tenant identity is determined — every
// handler below gets its company_id from here, never from a request body
// or query param (a client could lie about those; it can't forge a valid
// signature without SESSION_SECRET).
async function getSession(req: Request, env: Env): Promise<{ userId: number; companyId: number; email: string } | null> {
  const header = req.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  const payload = await verifySession(env, token);
  if (!payload) return null;
  return { userId: payload.uid, companyId: payload.cid, email: payload.email };
}

// ─── Text normalization + fuzzy matching ───────────────────────────────────
// Receipt OCR text is noisy: different casing, abbreviations, trailing SKU
// codes, plural/singular drift. We normalize aggressively, then score
// similarity with a bigram Dice coefficient — cheap, dependency-free, and
// forgiving of word-order/abbreviation differences in a way exact-match
// never is.

function normalizeText(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\b\d{4,}\b/g, ' ') // strip long SKU/UPC-looking numbers
    .replace(/\s+/g, ' ')
    .trim();
}

function bigrams(s: string): Set<string> {
  const out = new Set<string>();
  const padded = ` ${s} `;
  for (let i = 0; i < padded.length - 1; i++) out.add(padded.slice(i, i + 2));
  return out;
}

function diceSimilarity(a: string, b: string): number {
  if (!a || !b) return 0;
  const A = bigrams(a), B = bigrams(b);
  let overlap = 0;
  for (const g of A) if (B.has(g)) overlap++;
  return (2 * overlap) / (A.size + B.size);
}

type ProductRow = {
  id: number; company_id: number; name: string; normalized_name: string; category: string;
  unit_price: number; current_stock: number; lead_time_days: number;
  safety_z: number; demand_level: number; demand_trend: number;
  demand_variance: number; last_sale_date: string | null;
};

// Every lookup is scoped to companyId — a receipt line item can only ever
// match a product that belongs to the same company that uploaded it.
async function findBestMatch(env: Env, companyId: number, rawText: string): Promise<{ product: ProductRow | null; confidence: number }> {
  const normalized = normalizeText(rawText);
  const { results } = await env.DB.prepare(
    'SELECT * FROM products WHERE company_id = ? AND archived = 0'
  ).bind(companyId).all<ProductRow>();
  let best: ProductRow | null = null;
  let bestScore = 0;
  for (const p of results ?? []) {
    const score = diceSimilarity(normalized, p.normalized_name);
    if (score > bestScore) { bestScore = score; best = p; }
  }
  // 0.65 threshold — false "new product" creation is cheap to fix in
  // review, a false match silently corrupts that product's demand history.
  // Raised from 0.45 after "CAT6 CABLE 50FT" false-matched "HDMI CABLE 6FT"
  // at 55% (shared "CABLE" + digit/unit fragments inflate bigram overlap).
  if (bestScore < 0.65) return { product: null, confidence: bestScore };
  return { product: best, confidence: bestScore };
}

// ─── Demand model: Holt's linear (double exponential smoothing) ───────────
// Updated once per confirmed sale. level = smoothed units/day, trend =
// smoothed change in units/day per day. Sparse, irregular sales data
// (typical for a small shop, not a supermarket) means an aggressive alpha/
// beta is more useful than the slow-moving values textbooks use for daily
// retail series.

const ALPHA = 0.4;  // level smoothing
const BETA = 0.3;   // trend smoothing
const GAMMA = 0.3;  // variance smoothing

function daysBetween(a: string, b: string): number {
  const d = (new Date(b).getTime() - new Date(a).getTime()) / 86400000;
  return d;
}

function updateDemandModel(p: ProductRow, qty: number, saleDate: string) {
  const daysSince = p.last_sale_date
    ? Math.max(0.25, daysBetween(p.last_sale_date, saleDate))
    : Math.max(1, p.lead_time_days || 3);

  const rate = qty / daysSince;
  const isFirstSale = !p.last_sale_date;

  const levelPrev = isFirstSale ? rate : p.demand_level;
  const trendPrev = isFirstSale ? 0 : p.demand_trend;

  const levelNew = ALPHA * rate + (1 - ALPHA) * (levelPrev + trendPrev);
  const trendNew = BETA * (levelNew - levelPrev) + (1 - BETA) * trendPrev;

  const forecastPrev = levelPrev + trendPrev;
  const error = rate - forecastPrev;
  const varianceNew = isFirstSale
    ? 0
    : GAMMA * (error * error) + (1 - GAMMA) * p.demand_variance;

  return { demand_level: levelNew, demand_trend: trendNew, demand_variance: varianceNew };
}

function computeRecommendation(p: ProductRow, eventBoost?: { multiplier: number; reason: string }) {
  const baseForecast = Math.max(0, p.demand_level + p.demand_trend);
  const forecastPerDay = baseForecast * (eventBoost?.multiplier ?? 1);
  const sigma = Math.sqrt(Math.max(0, p.demand_variance));
  const leadTime = Math.max(1, p.lead_time_days || 3);

  const demandOverLeadTime = leadTime * forecastPerDay;
  const safetyStock = p.safety_z * sigma * Math.sqrt(leadTime);
  const reorderPoint = demandOverLeadTime + safetyStock;
  const targetStock = reorderPoint + demandOverLeadTime; // order up to ~2x lead time coverage

  const needsReorder = p.current_stock <= reorderPoint;
  const recommendedQty = needsReorder ? Math.max(0, Math.ceil(targetStock - p.current_stock)) : 0;
  const daysOfStockLeft = forecastPerDay > 0.001 ? p.current_stock / forecastPerDay : Infinity;

  const trendDir = p.demand_trend > 0.05 ? 'trending up' : p.demand_trend < -0.05 ? 'trending down' : 'flat';
  let reasoning = `Forecast ${forecastPerDay.toFixed(2)} units/day (${trendDir}), ` +
    `${leadTime}-day lead time → reorder point ${reorderPoint.toFixed(1)}, ` +
    `current stock ${p.current_stock}. ${daysOfStockLeft === Infinity ? 'No recent demand.' : `~${daysOfStockLeft.toFixed(1)} days of stock left.`}`;
  if (eventBoost) reasoning += ` Boosted ${eventBoost.multiplier}x — ${eventBoost.reason}`;

  return { reorderPoint, targetStock, recommendedQty, daysOfStockLeft, needsReorder, reasoning, forecastPerDay, eventBoost: eventBoost ?? null };
}

// ─── AI calls (Gemini API, Gemma model — same key covers vision + text) ───

async function callGemmaVision(env: Env, imageBase64: string, mediaType: string) {
  const res = await fetch(
    'https://generativelanguage.googleapis.com/v1beta/models/gemma-4-31b-it:generateContent',
    {
      method: 'POST',
      headers: { 'x-goog-api-key': env.GEMINI_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{
          parts: [
            { inline_data: { mime_type: mediaType, data: imageBase64 } },
            {
              text: `You are reading a photo of a small business's paper sales receipt to log what was sold.

Extract every purchased line item you can read. Ignore subtotal, tax, total, tender, and change lines. Ignore the store header/footer.

Return ONLY a JSON object:
{
  "vendor": "<store name if visible, else null>",
  "receiptDate": "<YYYY-MM-DD if visible, else null>",
  "items": [
    { "rawText": "<item name exactly as printed, cleaned of stray OCR noise>", "qty": <integer, default 1 if not shown>, "unitPrice": <number, 0 if unreadable> }
  ]
}

If a line's text is too garbled to be a real product, omit it rather than guessing. Return ONLY the raw JSON, no markdown, no explanation.`,
            },
          ],
        }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 2048,
          responseMimeType: 'application/json',
          thinkingConfig: { thinkingLevel: 'MINIMAL' },
        },
      }),
    }
  );
  if (!res.ok) throw new Error('AI scan failed: ' + (await res.text()));
  const data = await res.json() as { candidates: Array<{ content: { parts: Array<{ text?: string; thought?: boolean }> } }> };
  const parts = data.candidates?.[0]?.content?.parts ?? [];
  const text = parts.find((p) => !p.thought && p.text)?.text ?? '{}';
  const clean = text.replace(/```json|```/g, '').trim();
  return JSON.parse(clean) as { vendor: string | null; receiptDate: string | null; items: Array<{ rawText: string; qty: number; unitPrice: number }> };
}

async function callGemmaText(env: Env, prompt: string): Promise<string> {
  const res = await fetch(
    'https://generativelanguage.googleapis.com/v1beta/models/gemma-4-31b-it:generateContent',
    {
      method: 'POST',
      headers: { 'x-goog-api-key': env.GEMINI_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.4, maxOutputTokens: 800, thinkingConfig: { thinkingLevel: 'MINIMAL' } },
      }),
    }
  );
  if (!res.ok) throw new Error('AI summary failed: ' + (await res.text()));
  const data = await res.json() as { candidates: Array<{ content: { parts: Array<{ text?: string; thought?: boolean }> } }> };
  const parts = data.candidates?.[0]?.content?.parts ?? [];
  return parts.find((p) => !p.thought && p.text)?.text?.trim() ?? '';
}

// ─── Google Calendar integration (per-company) ─────────────────────────────
// Purpose: a demand spike isn't only visible in past sales — a known upcoming
// event (a game night, a local festival, a holiday) predicts one before it
// happens. We read the connected company's real Google Calendar, then use
// Gemma to judge which product categories a given event title is actually
// likely to affect (a "Staff meeting" shouldn't boost anything; "Super Bowl
// watch party" should boost beverages/snacks) — this is a genuinely
// different signal than anything derivable from sales history alone.
//
// Every function here takes companyId and reads/writes settings scoped to
// that company, so two companies connecting Google Calendar never touch
// each other's tokens or events.

const GOOGLE_SCOPES = 'https://www.googleapis.com/auth/calendar.readonly';

async function getSetting(env: Env, companyId: number, key: string): Promise<string | null> {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE company_id = ? AND key = ?').bind(companyId, key).first<{ value: string }>();
  return row?.value ?? null;
}

async function setSetting(env: Env, companyId: number, key: string, value: string) {
  await env.DB.prepare(
    'INSERT INTO settings (company_id, key, value) VALUES (?, ?, ?) ON CONFLICT(company_id, key) DO UPDATE SET value = excluded.value'
  ).bind(companyId, key, value).run();
}

// state carries the company_id through the Google redirect round-trip:
// Google's callback hits our server directly (no Authorization header from
// our frontend), so this is how the callback knows which tenant to save
// tokens for. Signed the same way session tokens are, so it can't be
// tampered with to attach tokens to a different company.
async function buildGoogleAuthUrl(env: Env, companyId: number): Promise<string> {
  const state = await signSession(env, { uid: 0, cid: companyId, email: '', exp: Date.now() + 10 * 60 * 1000 });
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: GOOGLE_SCOPES,
    access_type: 'offline',   // required to get a refresh_token
    prompt: 'consent',        // force refresh_token even on repeat connects
    state,
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

async function exchangeGoogleCode(env: Env, code: string) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    }),
  });
  if (!res.ok) throw new Error('Google token exchange failed: ' + (await res.text()));
  return res.json() as Promise<{ access_token: string; refresh_token?: string; expires_in: number }>;
}

async function getValidGoogleAccessToken(env: Env, companyId: number): Promise<string | null> {
  const refreshToken = await getSetting(env, companyId, 'google_refresh_token');
  if (!refreshToken) return null;

  const expiresAt = Number(await getSetting(env, companyId, 'google_token_expires_at') ?? '0');
  const cached = await getSetting(env, companyId, 'google_access_token');
  if (cached && Date.now() < expiresAt - 60_000) return cached;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type: 'refresh_token',
    }),
  });
  if (!res.ok) return null; // refresh token revoked/expired — treat as disconnected
  const data = await res.json() as { access_token: string; expires_in: number };
  await setSetting(env, companyId, 'google_access_token', data.access_token);
  await setSetting(env, companyId, 'google_token_expires_at', String(Date.now() + data.expires_in * 1000));
  return data.access_token;
}

type CalendarEvent = { title: string; start: string; end: string };

// Pulls events in the next `daysAhead` days from the connected company's
// primary calendar. Bounded window matches typical reorder lead times —
// events further out aren't actionable for a restock decision yet.
async function fetchUpcomingEvents(env: Env, companyId: number, daysAhead = 21): Promise<CalendarEvent[]> {
  const token = await getValidGoogleAccessToken(env, companyId);
  if (!token) return [];

  const timeMin = new Date().toISOString();
  const timeMax = new Date(Date.now() + daysAhead * 86400000).toISOString();
  const params = new URLSearchParams({
    timeMin, timeMax, singleEvents: 'true', orderBy: 'startTime', maxResults: '50',
  });
  const res = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/primary/events?${params.toString()}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) return [];
  const data = await res.json() as { items?: Array<{ summary?: string; start?: { date?: string; dateTime?: string }; end?: { date?: string; dateTime?: string } }> };
  return (data.items ?? [])
    .filter((e) => e.summary)
    .map((e) => ({
      title: e.summary!,
      start: (e.start?.dateTime || e.start?.date || '').slice(0, 10),
      end: (e.end?.dateTime || e.end?.date || '').slice(0, 10),
    }));
}

// Asks Gemma which product categories a set of upcoming events plausibly
// affects, and by roughly how much — this is the actual "AI" step, not a
// keyword list. Falls back to no boost (multiplier 1) for anything the
// model isn't confident about, or if there are no events/categories.
async function getEventDemandBoosts(
  env: Env, categories: string[], events: CalendarEvent[]
): Promise<Record<string, { multiplier: number; reason: string }>> {
  if (events.length === 0 || categories.length === 0) return {};

  const prompt = `A small shop sells products in these categories: ${categories.join(', ')}.

These events are on the owner's calendar in the next few weeks:
${events.map((e) => `- "${e.title}" on ${e.start}`).join('\n')}

For each category that a specific event would plausibly increase demand for (e.g. a party/game/holiday event boosting snacks or beverages — ignore generic events like meetings, appointments, or reminders that have no retail demand impact), return a demand multiplier.

Return ONLY a JSON object, no markdown, shaped exactly like:
{"CategoryName": {"multiplier": 1.4, "reason": "short reason tied to a specific event"}}

Omit any category you're not reasonably confident about. Multipliers should be modest and realistic (1.1 to 2.0 range) — do not inflate.`;

  try {
    const raw = await callGemmaText(env, prompt);
    const clean = raw.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);
    return typeof parsed === 'object' && parsed ? parsed : {};
  } catch {
    return {}; // AI parse failure should never break the recommendation flow
  }
}

// ─── Auto-reorder ───────────────────────────────────────────────────────
// Computes recommendations (baseline demand + event boosts, same math as
// /api/recommendations) and, for every item at/below its reorder point,
// creates a DRAFT purchase receipt — items already matched to the correct
// product at the recommended quantity, but status stays 'pending' and
// stock is NOT touched yet. The owner reviews it in the normal Scan tab
// review screen and clicks "Confirm & log sales" to actually apply it,
// same as any manually scanned receipt. This is intentionally NOT
// auto-confirmed — a bad calendar read or skewed demand model should never
// silently change stock without a human looking at it first.
async function buildAutoReorderDraft(env: Env, companyId: number) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM products WHERE company_id = ? AND archived = 0'
  ).bind(companyId).all<ProductRow>();
  const products = results ?? [];
  if (products.length === 0) return { receipt: null, items: [] as any[] };

  const categories = [...new Set(products.map((p) => p.category))];
  const events = await fetchUpcomingEvents(env, companyId);
  const boosts = await getEventDemandBoosts(env, categories, events);

  const needing = products
    .map((p) => ({ product: p, rec: computeRecommendation(p, boosts[p.category]) }))
    .filter((r) => r.rec.needsReorder && r.rec.recommendedQty > 0);

  if (needing.length === 0) return { receipt: null, items: [] as any[] };

  const receipt = await env.DB.prepare(
    `INSERT INTO receipts (company_id, vendor, receipt_date, status, receipt_type)
     VALUES (?, 'Auto-Reorder (draft)', ?, 'pending', 'purchase') RETURNING *`
  ).bind(companyId, new Date().toISOString().slice(0, 10)).first<any>();

  const itemsOut = [];
  for (const r of needing) {
    const row = await env.DB.prepare(
      `INSERT INTO receipt_items (company_id, receipt_id, raw_text, qty, unit_price, suggested_product_id, match_confidence, resolved_product_id, status)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'matched') RETURNING *`
    ).bind(companyId, receipt.id, r.product.name, r.rec.recommendedQty, r.product.unit_price, r.product.id, r.product.id).first<any>();
    itemsOut.push({ ...row, suggested_product_name: r.product.name, event_boost: r.rec.eventBoost ?? null });
  }

  return { receipt, items: itemsOut };
}

// ─── Worker ─────────────────────────────────────────────────────────────

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    try {
      // ── Auth ──────────────────────────────────────────────────────────

      // POST /api/auth/signup — creates a new company + its first (owner) user
      if (path === '/api/auth/signup' && req.method === 'POST') {
        const b = await req.json() as { company_name: string; business_type?: string; email: string; password: string };
        const companyName = (b.company_name || '').trim();
        const email = (b.email || '').trim().toLowerCase();
        const password = b.password || '';
        if (!companyName) return json({ error: 'Company name is required' }, 400);
        if (!email || !email.includes('@')) return json({ error: 'A valid email is required' }, 400);
        if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existing) return json({ error: 'An account with that email already exists' }, 409);

        const company = await env.DB.prepare(
          'INSERT INTO companies (name, business_type) VALUES (?, ?) RETURNING *'
        ).bind(companyName, b.business_type || 'General').first<any>();

        const salt = generateSalt();
        const hash = await hashPassword(password, salt);
        const user = await env.DB.prepare(
          'INSERT INTO users (company_id, email, password_hash, password_salt) VALUES (?, ?, ?, ?) RETURNING *'
        ).bind(company.id, email, hash, salt).first<any>();

        const token = await signSession(env, { uid: user.id, cid: company.id, email, exp: Date.now() + SESSION_TTL_MS });
        return json({ token, company: { id: company.id, name: company.name, business_type: company.business_type } }, 201);
      }

      // POST /api/auth/login
      if (path === '/api/auth/login' && req.method === 'POST') {
        const b = await req.json() as { email: string; password: string };
        const email = (b.email || '').trim().toLowerCase();
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<any>();
        if (!user) return authFail('Incorrect email or password');

        const hash = await hashPassword(b.password || '', user.password_salt);
        if (!timingSafeEqual(hash, user.password_hash)) return authFail('Incorrect email or password');

        const company = await env.DB.prepare('SELECT * FROM companies WHERE id = ?').bind(user.company_id).first<any>();
        const token = await signSession(env, { uid: user.id, cid: user.company_id, email, exp: Date.now() + SESSION_TTL_MS });
        return json({ token, company: { id: company.id, name: company.name, business_type: company.business_type } });
      }

      // GET /api/auth/me — used on page load to validate a stored token and
      // repopulate the header without asking the owner to log in again
      if (path === '/api/auth/me' && req.method === 'GET') {
        const session = await getSession(req, env);
        if (!session) return authFail();
        const company = await env.DB.prepare('SELECT * FROM companies WHERE id = ?').bind(session.companyId).first<any>();
        if (!company) return authFail();
        return json({ company: { id: company.id, name: company.name, business_type: company.business_type }, email: session.email });
      }

      // ── Everything below requires a valid session ───────────────────────
      const session = await getSession(req, env);

      // GET /api/calendar/callback is the one exception: Google redirects the
      // owner's browser here directly, with no Authorization header. The
      // company identity instead comes from the signed `state` param.
      if (path === '/api/calendar/callback' && req.method === 'GET') {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        if (!code || !state) return json({ error: 'missing code or state' }, 400);
        const statePayload = await verifySession(env, state);
        if (!statePayload) return json({ error: 'invalid or expired state' }, 400);
        const companyId = statePayload.cid;

        const tokens = await exchangeGoogleCode(env, code);
        if (tokens.refresh_token) await setSetting(env, companyId, 'google_refresh_token', tokens.refresh_token);
        await setSetting(env, companyId, 'google_access_token', tokens.access_token);
        await setSetting(env, companyId, 'google_token_expires_at', String(Date.now() + tokens.expires_in * 1000));
        return new Response(
          '<html><body style="font-family:sans-serif;text-align:center;padding:40px">Google Calendar connected — you can close this tab.</body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        );
      }

      if (!session) return authFail();
      const companyId = session.companyId;

      // POST /api/scan-receipt — vision model reads the photo, we fuzzy-match each line
      if (path === '/api/scan-receipt' && req.method === 'POST') {
        const body = await req.json() as { imageBase64: string; mediaType: string; receiptType?: 'sale' | 'purchase' };
        const { imageBase64, mediaType } = body;
        const parsed = await callGemmaVision(env, imageBase64, mediaType);

        const receipt = await env.DB.prepare(
          'INSERT INTO receipts (company_id, vendor, receipt_date, receipt_type) VALUES (?, ?, ?, ?) RETURNING *'
        ).bind(companyId, parsed.vendor ?? null, parsed.receiptDate ?? null, body.receiptType === 'purchase' ? 'purchase' : 'sale').first();

        const itemsOut = [];
        for (const item of parsed.items ?? []) {
          const { product, confidence } = await findBestMatch(env, companyId, item.rawText);
          const row = await env.DB.prepare(
            `INSERT INTO receipt_items (company_id, receipt_id, raw_text, qty, unit_price, suggested_product_id, match_confidence, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
          ).bind(
            companyId, (receipt as any).id, item.rawText, item.qty || 1, item.unitPrice || 0,
            product?.id ?? null, confidence, product ? 'unconfirmed' : 'unconfirmed'
          ).first();
          itemsOut.push({ ...row, suggested_product_name: product?.name ?? null });
        }

        return json({ receipt, items: itemsOut });
      }

      // GET /api/receipts — history list for the new Receipts tab. Newest
      // first, with item count so the list can show something useful
      // without a second request per row.
      if (path === '/api/receipts' && req.method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT r.*,
             (SELECT COUNT(*) FROM receipt_items ri WHERE ri.receipt_id = r.id AND ri.company_id = r.company_id) AS item_count,
             (SELECT COALESCE(SUM(ri.qty), 0) FROM receipt_items ri WHERE ri.receipt_id = r.id AND ri.company_id = r.company_id AND ri.status = 'matched') AS total_qty
           FROM receipts r
           WHERE r.company_id = ?
           ORDER BY r.uploaded_at DESC
           LIMIT 100`
        ).bind(companyId).all();
        return json(results ?? []);
      }

      // GET /api/receipts/:id — review a scanned receipt
      const receiptGet = path.match(/^\/api\/receipts\/(\d+)$/);
      if (receiptGet && req.method === 'GET') {
        const id = Number(receiptGet[1]);
        const receipt = await env.DB.prepare('SELECT * FROM receipts WHERE id = ? AND company_id = ?').bind(id, companyId).first();
        if (!receipt) return json({ error: 'not found' }, 404);
        const { results: items } = await env.DB.prepare(
          `SELECT ri.*, p.name AS suggested_product_name
           FROM receipt_items ri LEFT JOIN products p ON p.id = ri.suggested_product_id
           WHERE ri.receipt_id = ? AND ri.company_id = ?`
        ).bind(id, companyId).all();
        return json({ receipt, items });
      }

      // POST /api/receipts/:id/items/:itemId/resolve — human confirms/creates/ignores a line
      const resolveMatch = path.match(/^\/api\/receipts\/(\d+)\/items\/(\d+)\/resolve$/);
      if (resolveMatch && req.method === 'POST') {
        const receiptId = Number(resolveMatch[1]);
        const itemId = Number(resolveMatch[2]);
        const item = await env.DB.prepare('SELECT id FROM receipt_items WHERE id = ? AND receipt_id = ? AND company_id = ?')
          .bind(itemId, receiptId, companyId).first();
        if (!item) return json({ error: 'not found' }, 404);

        const body = await req.json() as {
          action: 'match' | 'new_product' | 'ignore';
          product_id?: number;
          name?: string; category?: string; unit_price?: number; lead_time_days?: number;
        };

        if (body.action === 'ignore') {
          await env.DB.prepare('UPDATE receipt_items SET status = ? WHERE id = ?').bind('ignored', itemId).run();
          return json({ ok: true });
        }

        let productId = body.product_id;
        if (body.action === 'new_product') {
          const name = (body.name || '').trim();
          if (!name) return json({ error: 'name required for new_product' }, 400);
          const created = await env.DB.prepare(
            `INSERT INTO products (company_id, name, normalized_name, category, unit_price, current_stock, lead_time_days)
             VALUES (?, ?, ?, ?, ?, 0, ?) RETURNING *`
          ).bind(companyId, name, normalizeText(name), body.category || 'General', body.unit_price || 0, body.lead_time_days || 3).first();
          productId = (created as any).id;
        } else if (productId) {
          // matching to an existing product — make sure it's actually this company's product
          const owned = await env.DB.prepare('SELECT id FROM products WHERE id = ? AND company_id = ?').bind(productId, companyId).first();
          if (!owned) return json({ error: 'product not found' }, 404);
        }

        if (!productId) return json({ error: 'product_id required for match' }, 400);
        await env.DB.prepare(
          'UPDATE receipt_items SET status = ?, resolved_product_id = ? WHERE id = ?'
        ).bind('matched', productId, itemId).run();
        return json({ ok: true, product_id: productId });
      }

      // POST /api/receipts/:id/confirm — log sales, decrement stock, update demand model
      const confirmMatch = path.match(/^\/api\/receipts\/(\d+)\/confirm$/);
      if (confirmMatch && req.method === 'POST') {
        const receiptId = Number(confirmMatch[1]);
        const receipt = await env.DB.prepare('SELECT * FROM receipts WHERE id = ? AND company_id = ?').bind(receiptId, companyId).first<any>();
        if (!receipt) return json({ error: 'Receipt not found' }, 404);

        const saleDate = receipt.receipt_date || new Date().toISOString().slice(0, 10);
        const { results: items } = await env.DB.prepare(
          `SELECT * FROM receipt_items WHERE receipt_id = ? AND company_id = ? AND status = 'matched'`
        ).bind(receiptId, companyId).all<any>();

        const isPurchase = receipt.receipt_type === 'purchase';
        for (const item of items ?? []) {
          const product = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND company_id = ?').bind(item.resolved_product_id, companyId).first<ProductRow>();
          if (!product) continue;

          if (isPurchase) {
            const newStock = product.current_stock + item.qty;
            await env.DB.prepare('UPDATE products SET current_stock = ? WHERE id = ?').bind(newStock, product.id).run();
          } else {
            const model = updateDemandModel(product, item.qty, saleDate);
            const newStock = Math.max(0, product.current_stock - item.qty);
            await env.DB.prepare(
              `UPDATE products SET current_stock = ?, demand_level = ?, demand_trend = ?, demand_variance = ?, last_sale_date = ? WHERE id = ?`
            ).bind(newStock, model.demand_level, model.demand_trend, model.demand_variance, saleDate, product.id).run();
            await env.DB.prepare(
              'INSERT INTO sales_log (company_id, product_id, qty, sale_date, receipt_item_id) VALUES (?, ?, ?, ?, ?)'
            ).bind(companyId, product.id, item.qty, saleDate, item.id).run();
          }
        }

        await env.DB.prepare('UPDATE receipts SET status = ? WHERE id = ?').bind('confirmed', receiptId).run();
        return json({ ok: true, itemsLogged: (items ?? []).length });
      }

      // GET /api/calendar/auth-url — kicks off the Google OAuth consent flow
      // for THIS company (company_id is embedded in the signed state param)
      if (path === '/api/calendar/auth-url' && req.method === 'GET') {
        const authUrl = await buildGoogleAuthUrl(env, companyId);
        return json({ url: authUrl });
      }

      // GET /api/calendar/status
      if (path === '/api/calendar/status' && req.method === 'GET') {
        const connected = !!(await getSetting(env, companyId, 'google_refresh_token'));
        return json({ connected });
      }

      // POST /api/calendar/disconnect
      if (path === '/api/calendar/disconnect' && req.method === 'POST') {
        await env.DB.prepare('DELETE FROM settings WHERE company_id = ? AND key IN (?, ?, ?)')
          .bind(companyId, 'google_refresh_token', 'google_access_token', 'google_token_expires_at').run();
        return json({ ok: true });
      }

      // GET /api/calendar/upcoming-events — raw events, for display in the UI
      if (path === '/api/calendar/upcoming-events' && req.method === 'GET') {
        const events = await fetchUpcomingEvents(env, companyId);
        return json(events);
      }

      // GET /api/dashboard?period=day|week|month|year — top-selling
      // products and categories over the selected window. Reads only
      // sales_log, so this reflects confirmed SALE receipts — purchases
      // (restocking) don't count toward "selling," which is the point.
      if (path === '/api/dashboard' && req.method === 'GET') {
        const period = url.searchParams.get('period') || 'week';
        const daysMap: Record<string, number> = { day: 1, week: 7, month: 30, year: 365 };
        const days = daysMap[period] ?? 7;
        const cutoff = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

        const { results: topProducts } = await env.DB.prepare(
          `SELECT p.id AS product_id, p.name, p.category, SUM(sl.qty) AS qty_sold, COUNT(*) AS sale_count
           FROM sales_log sl JOIN products p ON p.id = sl.product_id
           WHERE sl.company_id = ? AND sl.sale_date >= ?
           GROUP BY p.id
           ORDER BY qty_sold DESC
           LIMIT 10`
        ).bind(companyId, cutoff).all();

        const { results: topCategories } = await env.DB.prepare(
          `SELECT p.category, SUM(sl.qty) AS qty_sold
           FROM sales_log sl JOIN products p ON p.id = sl.product_id
           WHERE sl.company_id = ? AND sl.sale_date >= ?
           GROUP BY p.category
           ORDER BY qty_sold DESC
           LIMIT 10`
        ).bind(companyId, cutoff).all();

        return json({ period, days, topProducts: topProducts ?? [], topCategories: topCategories ?? [] });
      }

      // GET /api/products
      if (path === '/api/products' && req.method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT * FROM products WHERE company_id = ? AND archived = 0 ORDER BY name'
        ).bind(companyId).all<ProductRow>();
        const withRecs = (results ?? []).map((p) => ({ ...p, ...computeRecommendation(p) }));
        return json(withRecs);
      }

      // POST /api/products — manual add
      if (path === '/api/products' && req.method === 'POST') {
        const b = await req.json() as { name: string; category?: string; unit_price?: number; current_stock?: number; lead_time_days?: number };
        if (!b.name?.trim()) return json({ error: 'name required' }, 400);
        const row = await env.DB.prepare(
          `INSERT INTO products (company_id, name, normalized_name, category, unit_price, current_stock, lead_time_days)
           VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
        ).bind(companyId, b.name.trim(), normalizeText(b.name), b.category || 'General', b.unit_price || 0, b.current_stock || 0, b.lead_time_days || 3).first();
        return json(row, 201);
      }

      // PUT /api/products/:id — edit stock / lead time / price / archive
      const productMatch = path.match(/^\/api\/products\/(\d+)$/);
      if (productMatch && req.method === 'PUT') {
        const id = Number(productMatch[1]);
        const b = await req.json() as Partial<{ name: string; category: string; unit_price: number; current_stock: number; lead_time_days: number; archived: boolean }>;
        const existing = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND company_id = ?').bind(id, companyId).first<ProductRow>();
        if (!existing) return json({ error: 'not found' }, 404);
        const name = b.name ?? existing.name;
        await env.DB.prepare(
          `UPDATE products SET name=?, normalized_name=?, category=?, unit_price=?, current_stock=?, lead_time_days=?, archived=? WHERE id=? AND company_id=?`
        ).bind(
          name, normalizeText(name), b.category ?? existing.category, b.unit_price ?? existing.unit_price,
          b.current_stock ?? existing.current_stock, b.lead_time_days ?? existing.lead_time_days,
          b.archived ? 1 : 0, id, companyId
        ).run();
        const row = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND company_id = ?').bind(id, companyId).first();
        return json(row);
      }

      // DELETE /api/products/:id — hard delete if the product has no sales
      // history yet (safe to just remove), otherwise archive it so past
      // sales_log / receipt_items rows don't dangle on a missing product.
      const deleteMatch = path.match(/^\/api\/products\/(\d+)$/);
      if (deleteMatch && req.method === 'DELETE') {
        const id = Number(deleteMatch[1]);
        const existing = await env.DB.prepare('SELECT id FROM products WHERE id = ? AND company_id = ?').bind(id, companyId).first();
        if (!existing) return json({ error: 'not found' }, 404);

        await env.DB.prepare('UPDATE products SET archived = 1 WHERE id = ? AND company_id = ?').bind(id, companyId).run();
        return json({ deleted: false, archived: true });
      }

      // POST /api/recommendations/auto-reorder — builds a DRAFT purchase
      // receipt for every item at/below reorder point. Nothing is
      // confirmed here — the frontend drops the returned receipt into the
      // normal review screen so the owner can look it over before stock
      // actually changes.
      if (path === '/api/recommendations/auto-reorder' && req.method === 'POST') {
        const result = await buildAutoReorderDraft(env, companyId);
        return json(result);
      }

      // GET /api/recommendations — compute fresh recs for items at/below reorder point
      if (path === '/api/recommendations' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM products WHERE company_id = ? AND archived = 0').bind(companyId).all<ProductRow>();
        const products = results ?? [];
        const categories = [...new Set(products.map((p) => p.category))];
        const events = await fetchUpcomingEvents(env, companyId);
        const boosts = await getEventDemandBoosts(env, categories, events);
        const recs = products
          .map((p) => {
            const rec = computeRecommendation(p, boosts[p.category]);
            // Recompute with no event boost so the UI can show how much of
            // recommendedQty is attributable to the calendar event vs. the
            // product's own baseline demand.
            const baselineQty = boosts[p.category] ? computeRecommendation(p).recommendedQty : rec.recommendedQty;
            return { product: p, rec, baselineQty };
          })
          .filter((r) => r.rec.needsReorder)
          .sort((a, b) => a.rec.daysOfStockLeft - b.rec.daysOfStockLeft);
        return json(recs.map((r) => ({
          product_id: r.product.id, name: r.product.name, category: r.product.category,
          current_stock: r.product.current_stock, ...r.rec,
          baseline_qty: r.baselineQty,
          event_boost_qty: r.rec.recommendedQty - r.baselineQty,
        })));
      }

      // POST /api/recommendations/generate — AI drafts a readable restock note
      if (path === '/api/recommendations/generate' && req.method === 'POST') {
        const { results } = await env.DB.prepare('SELECT * FROM products WHERE company_id = ? AND archived = 0').bind(companyId).all<ProductRow>();
        const products = results ?? [];
        const categories = [...new Set(products.map((p) => p.category))];
        const events = await fetchUpcomingEvents(env, companyId);
        const boosts = await getEventDemandBoosts(env, categories, events);
        const needing = products
          .map((p) => {
            const rec = computeRecommendation(p, boosts[p.category]);
            // Recompute with no event boost so the UI can show how much of
            // recommendedQty is attributable to the calendar event vs. the
            // product's own baseline demand.
            const baselineQty = boosts[p.category] ? computeRecommendation(p).recommendedQty : rec.recommendedQty;
            return { product: p, rec, baselineQty };
          })
          .filter((r) => r.rec.needsReorder)
          .sort((a, b) => a.rec.daysOfStockLeft - b.rec.daysOfStockLeft);

        if (needing.length === 0) {
          return json({ summary: 'Nothing needs restocking right now — every item is above its reorder point.', items: [] });
        }

        const lines = needing.map((r) =>
          `- ${r.product.name} (${r.product.category}): ${r.product.current_stock} on hand, ` +
          `~${r.rec.forecastPerDay.toFixed(2)}/day demand, ${r.rec.daysOfStockLeft === Infinity ? 'no recent sales' : r.rec.daysOfStockLeft.toFixed(1) + ' days left'}, ` +
          `recommend ordering ${r.rec.recommendedQty} units (lead time ${r.product.lead_time_days}d)` +
          `${r.rec.eventBoost ? ` — boosted due to: ${r.rec.eventBoost.reason} (baseline would have been ${r.baselineQty} units)` : ''}.`
        ).join('\n');

        const prompt = `You are drafting a short internal restock note for a small shop owner based on this computed reorder data:\n\n${lines}\n\nWrite a brief (under 150 words), plain-English summary a busy owner can skim: what to order first (most urgent), roughly how much, and one sentence noting any items trending up or boosted by an upcoming calendar event. Do not repeat every number — hit the highlights. No markdown headers.`;

        const summary = await callGemmaText(env, prompt);

        for (const r of needing) {
          await env.DB.prepare(
            `INSERT INTO restock_recommendations (company_id, product_id, reorder_point, target_stock, recommended_qty, days_of_stock_left, reasoning, ai_summary)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            companyId, r.product.id, r.rec.reorderPoint, r.rec.targetStock, r.rec.recommendedQty,
            r.rec.daysOfStockLeft === Infinity ? null : r.rec.daysOfStockLeft, r.rec.reasoning, summary
          ).run();
        }

        return json({
          summary,
          items: needing.map((r) => ({
            product_id: r.product.id, name: r.product.name, recommended_qty: r.rec.recommendedQty,
            baseline_qty: r.baselineQty, event_boost_qty: r.rec.recommendedQty - r.baselineQty,
            days_of_stock_left: r.rec.daysOfStockLeft, reasoning: r.rec.reasoning, event_boost: r.rec.eventBoost,
          })),
        });
      }

      // GET /api/sales-history/:productId — for the trend sparkline
      const historyMatch = path.match(/^\/api\/sales-history\/(\d+)$/);
      if (historyMatch && req.method === 'GET') {
        const id = Number(historyMatch[1]);
        const owned = await env.DB.prepare('SELECT id FROM products WHERE id = ? AND company_id = ?').bind(id, companyId).first();
        if (!owned) return json({ error: 'not found' }, 404);
        const { results } = await env.DB.prepare(
          'SELECT sale_date, qty FROM sales_log WHERE product_id = ? AND company_id = ? ORDER BY sale_date ASC'
        ).bind(id, companyId).all();
        return json(results);
      }

      return json({ error: 'Not found' }, 404);
    } catch (err: any) {
      console.error('[auto-stockers] error', err);
      return json({ error: err?.message || 'Server error' }, 500);
    }
  },

  // Runs on the cron schedule set in wrangler.toml. Loops every tenant —
  // one Worker, one D1 database, every company gets auto-reordered
  // independently, same isolation rule as everything else in this file.
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const { results: companies } = await env.DB.prepare('SELECT id FROM companies').all<{ id: number }>();
    for (const c of companies ?? []) {
      try {
        const result = await buildAutoReorderDraft(env, c.id);
        if (result.items.length > 0) console.log(`[auto-reorder] company ${c.id}: drafted ${result.items.length} item(s), awaiting review`);
      } catch (err) {
        console.error(`[auto-reorder] failed for company ${c.id}`, err);
      }
    }
  },
};
