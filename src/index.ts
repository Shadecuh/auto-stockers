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

// ─── D1 migration required for the AI Business Assistant ─────────────────
// Run once, e.g.: wrangler d1 execute <your-db-name> --command "..."
//
// CREATE TABLE IF NOT EXISTS assistant_messages (
//   id INTEGER PRIMARY KEY AUTOINCREMENT,
//   company_id INTEGER NOT NULL,
//   role TEXT NOT NULL,        -- 'user' | 'assistant'
//   message TEXT NOT NULL,
//   created_at TEXT NOT NULL DEFAULT (datetime('now'))
// );
// CREATE INDEX IF NOT EXISTS idx_assistant_messages_company
//   ON assistant_messages(company_id, created_at);

// ─── D1 migration required for cost_price + the AI report/view builder ────
// Run these against your EXISTING remote DB — do NOT re-run schema.sql,
// it DROPs every table. Replace <your-db-name> with your D1 database name.
//
//   wrangler d1 execute <your-db-name> --remote --command "ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0;"
//
//   wrangler d1 execute <your-db-name> --remote --command "CREATE TABLE IF NOT EXISTS saved_views (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, name TEXT NOT NULL, spec_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), FOREIGN KEY (company_id) REFERENCES companies(id));"
//
//   wrangler d1 execute <your-db-name> --remote --command "CREATE INDEX IF NOT EXISTS idx_saved_views_company ON saved_views(company_id, created_at);"
//
// (Drop --remote to run against your local/dev D1 instead.)

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
  unit_price: number; cost_price: number; current_stock: number; lead_time_days: number;
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

// ─── AI Business Assistant ──────────────────────────────────────────────
// A chat interface over the owner's OWN data — best sellers, what's
// overstocked, category trends, expansion ideas. Deliberately read-only:
// it reasons over a pre-computed snapshot and never touches `products`
// itself, same "human stays in the loop" spirit as auto-reorder.

// Pulls exactly the numbers the assistant is allowed to reason about. The
// LLM never gets raw SQL access — only this pre-computed, already-scoped
// summary — so it can't invent or leak figures from nowhere or from
// another tenant.
async function buildBusinessSnapshot(env: Env, companyId: number) {
  const { results: products } = await env.DB.prepare(
    'SELECT * FROM products WHERE company_id = ? AND archived = 0'
  ).bind(companyId).all<ProductRow>();

  const cutoff30 = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const cutoff90 = new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10);

  const { results: sales30 } = await env.DB.prepare(
    `SELECT p.id, p.name, p.category, SUM(sl.qty) AS qty_sold, SUM(sl.qty * p.unit_price) AS revenue
     FROM sales_log sl JOIN products p ON p.id = sl.product_id
     WHERE sl.company_id = ? AND sl.sale_date >= ?
     GROUP BY p.id ORDER BY qty_sold DESC`
  ).bind(companyId, cutoff30).all<{ id: number; name: string; category: string; qty_sold: number; revenue: number }>();

  const { results: sales90 } = await env.DB.prepare(
    `SELECT p.id, SUM(sl.qty) AS qty_sold
     FROM sales_log sl JOIN products p ON p.id = sl.product_id
     WHERE sl.company_id = ? AND sl.sale_date >= ?
     GROUP BY p.id`
  ).bind(companyId, cutoff90).all<{ id: number; qty_sold: number }>();

  const sold90Ids = new Set((sales90 ?? []).map((s) => s.id));
  const withRec = (products ?? []).map((p) => ({ ...p, ...computeRecommendation(p) }));

  const lowStock = withRec.filter((p) => p.needsReorder);
  // "Overstocked": plenty of stock, but demand is weak or flat — candidates
  // to buy less of. daysOfStockLeft can be Infinity for zero-demand items.
  const overstocked = withRec
    .filter((p) => p.current_stock > 0 && (p.daysOfStockLeft === Infinity || p.daysOfStockLeft > 90))
    .sort((a, b) => b.current_stock - a.current_stock)
    .slice(0, 10);
  const deadStock = (products ?? []).filter((p) => !sold90Ids.has(p.id) && p.current_stock > 0);

  const catTotals: Record<string, number> = {};
  const catRevenue: Record<string, number> = {};
  for (const s of sales30 ?? []) {
    catTotals[s.category] = (catTotals[s.category] || 0) + s.qty_sold;
    catRevenue[s.category] = (catRevenue[s.category] || 0) + s.revenue;
  }
  const topCategories = Object.entries(catTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([category, qty]) => ({ category, qty, revenue: Math.round(catRevenue[category] || 0) }));

  const trendingUp = withRec.filter((p) => p.demand_trend > 0.05).sort((a, b) => b.demand_trend - a.demand_trend).slice(0, 5);
  const trendingDown = withRec.filter((p) => p.demand_trend < -0.05).sort((a, b) => a.demand_trend - b.demand_trend).slice(0, 5);

  // Margin: real if a purchase receipt has scanned a cost_price, otherwise
  // estimated at DEFAULT_MARGIN_PCT — same fallback the Products table
  // uses, kept in sync so the assistant's numbers match what the owner sees.
  const DEFAULT_MARGIN_PCT = 30;
  const withMargin = (products ?? [])
    .filter((p) => Number(p.unit_price) > 0)
    .map((p) => {
      const price = Number(p.unit_price);
      const scannedCost = Number(p.cost_price) || 0;
      const estimated = scannedCost <= 0;
      const cost = estimated ? price * (1 - DEFAULT_MARGIN_PCT / 100) : scannedCost;
      const marginDollars = price - cost;
      const marginPct = estimated ? DEFAULT_MARGIN_PCT : Math.round((marginDollars / price) * 100);
      return { id: p.id, name: p.name, category: p.category, price, cost, marginDollars, marginPct, estimated, current_stock: p.current_stock };
    });
  const topMargin = [...withMargin].sort((a, b) => b.marginDollars - a.marginDollars).slice(0, 10);
  const totalCOGS = withMargin.reduce((sum, p) => sum + p.cost * p.current_stock, 0);
  const cogsIsFullyEstimated = withMargin.every((p) => p.estimated);

  // COST OF GOODS SOLD — what units actually sold in the last 30 days cost
  // (as opposed to totalCOGS above, which values everything still on the
  // shelf). Same real-vs-estimated cost per product, just multiplied by
  // qty_sold instead of current_stock.
  const costById = new Map(withMargin.map((p) => [p.id, p]));
  let cogsSold30d = 0;
  let soldItemsAllEstimated = true;
  let anySoldItemsMatched = false;
  for (const s of sales30 ?? []) {
    const m = costById.get(s.id);
    if (!m) continue;
    anySoldItemsMatched = true;
    cogsSold30d += m.cost * s.qty_sold;
    if (!m.estimated) soldItemsAllEstimated = false;
  }

  return {
    productCount: products?.length ?? 0,
    topSellers30d: (sales30 ?? []).slice(0, 10),
    topCategories30d: topCategories,
    lowStock: lowStock.map((p) => ({ name: p.name, category: p.category, current_stock: p.current_stock, days_left: p.daysOfStockLeft })),
    overstocked: overstocked.map((p) => ({ name: p.name, category: p.category, current_stock: p.current_stock, days_left: p.daysOfStockLeft === Infinity ? null : p.daysOfStockLeft })),
    deadStock90d: deadStock.map((p) => ({ name: p.name, category: p.category, current_stock: p.current_stock })),
    trendingUp: trendingUp.map((p) => ({ name: p.name, trend: p.demand_trend.toFixed(2) })),
    trendingDown: trendingDown.map((p) => ({ name: p.name, trend: p.demand_trend.toFixed(2) })),
    topMargin,
    totalCOGS: Math.round(totalCOGS),
    cogsIsFullyEstimated,
    cogsSold30d: Math.round(cogsSold30d),
    cogsSold30dEstimated: anySoldItemsMatched ? soldItemsAllEstimated : null, // null = no sales to measure
  };
}

// Turns the snapshot into short, labeled lines the model can cite directly
// instead of a raw JSON blob — cuts down on the model paraphrasing numbers
// wrong, and only includes sections that actually have data.
function formatSnapshotForPrompt(s: Awaited<ReturnType<typeof buildBusinessSnapshot>>): string {
  const lines: string[] = [`Total active products: ${s.productCount}`];

  if (s.topSellers30d.length) {
    lines.push('\nTOP SELLERS (last 30 days):');
    s.topSellers30d.forEach((p, i) => lines.push(`${i + 1}. ${p.name} (${p.category}) — ${p.qty_sold} sold, $${Math.round(p.revenue)} revenue`));
  }
  if (s.topCategories30d.length) {
    lines.push('\nTOP CATEGORIES (last 30 days):');
    s.topCategories30d.forEach((c) => lines.push(`- ${c.category}: ${c.qty} units, $${c.revenue} revenue`));
  }
  if (s.lowStock.length) {
    lines.push('\nLOW STOCK / NEEDS REORDER:');
    s.lowStock.forEach((p) => lines.push(`- ${p.name} (${p.category}): ${p.current_stock} on hand, ~${p.days_left === Infinity ? 'unknown' : p.days_left.toFixed(1)} days left`));
  }
  if (s.overstocked.length) {
    lines.push('\nOVERSTOCKED (high stock, slow demand — candidates to buy less of):');
    s.overstocked.forEach((p) => lines.push(`- ${p.name} (${p.category}): ${p.current_stock} on hand, ${p.days_left === null ? 'no recent demand' : p.days_left.toFixed(0) + ' days of stock left'}`));
  }
  if (s.deadStock90d.length) {
    lines.push('\nNO SALES IN 90+ DAYS (still in stock):');
    s.deadStock90d.forEach((p) => lines.push(`- ${p.name} (${p.category}): ${p.current_stock} on hand`));
  }
  if (s.trendingUp.length) {
    lines.push('\nTRENDING UP:');
    s.trendingUp.forEach((p) => lines.push(`- ${p.name} (trend +${p.trend}/day)`));
  }
  if (s.trendingDown.length) {
    lines.push('\nTRENDING DOWN:');
    s.trendingDown.forEach((p) => lines.push(`- ${p.name} (trend ${p.trend}/day)`));
  }
  if (s.topMargin.length) {
    lines.push('\nHIGHEST PROFIT MARGIN (top 10, sorted by $ margin per unit):');
    s.topMargin.forEach((p, i) => lines.push(
      `${i + 1}. ${p.name} (${p.category}) — sells for $${p.price.toFixed(2)}, cost $${p.cost.toFixed(2)}, margin $${p.marginDollars.toFixed(2)} (${p.marginPct}%)${p.estimated ? ' [estimated cost — no purchase receipt scanned yet]' : ''}`
    ));
  }
  lines.push(`\nTOTAL COST OF GOODS ON HAND (current stock valued at cost): $${s.totalCOGS.toLocaleString()}${s.cogsIsFullyEstimated ? ' [fully estimated — no items have a scanned purchase cost yet]' : ' [mix of scanned and estimated costs]'}`);
  if (s.cogsSold30dEstimated !== null) {
    lines.push(`COST OF GOODS SOLD (last 30 days, what sold units actually cost): $${s.cogsSold30d.toLocaleString()}${s.cogsSold30dEstimated ? ' [fully estimated]' : ' [mix of scanned and estimated costs]'}`);
  }
  return lines.join('\n');
}

const ASSISTANT_SYSTEM_PROMPT = `You are the Auto Stockers business assistant. You help a small business owner make inventory and buying decisions.

Rules:
1. Use ONLY the BUSINESS DATA block below as your source of numbers. Never invent a product name, quantity, or dollar figure that isn't in it.
2. If the data needed to answer isn't in the BUSINESS DATA block, say so plainly rather than guessing.
3. When asked "what should I buy less of" or similar, point to items in OVERSTOCKED or NO SALES IN 90+ DAYS, and explain why using the numbers given.
3a. When asked about profit, margin, or "what makes me the most money," use the HIGHEST PROFIT MARGIN list — cost is already computed for you (real where scanned, otherwise estimated at a 70%-of-price default). Never recompute cost or margin yourself from the price alone. If asked specifically for "cost of goods sold" or "COGS," use the COST OF GOODS SOLD line (what units sold in the last 30 days actually cost) — do not substitute TOTAL COST OF GOODS ON HAND, which is a different number (current shelf inventory valued at cost, not sales). If the owner's phrasing is ambiguous between the two, briefly clarify which one you're answering. If a figure is marked estimated, say so plainly and mention that scanning a purchase receipt would make it exact.
4. When asked about expansion ("what should I expand into"), reason from TOP CATEGORIES and TRENDING UP — suggest categories or adjacent products a shop like this could add, but be explicit that this is a suggestion based on their own sales pattern, not a guarantee.
5. Be direct and concise — a busy owner is skimming this, not reading a report. Prefer short paragraphs or a few bullet points over long prose.
6. You may reference recent conversation to resolve follow-ups like "why?" or "how much of that", but never treat prior conversation as a source of new facts.
7. Do not give legal, tax, or accounting advice — stick to inventory and product-mix reasoning.`;

async function callAssistantLLM(env: Env, snapshotText: string, history: string, userMessage: string): Promise<string> {
  const prompt =
    ASSISTANT_SYSTEM_PROMPT +
    '\n\nBUSINESS DATA:\n' + snapshotText +
    (history ? '\n\nRECENT CONVERSATION:\n' + history : '') +
    '\n\nOwner: ' + userMessage +
    '\nAssistant:';
  const reply = await callGemmaText(env, prompt);
  return reply || "Sorry, I couldn't put that together right now — try again in a moment.";
}

// ─── AI Report/View Builder ─────────────────────────────────────────────
// Owner describes a report in plain English ("products where I'll run out
// before the vendor's lead time"). The AI's ONLY job is to translate that
// into a JSON "spec" — never SQL. Every field name in the spec is checked
// against QUERY_WHITELIST before it touches a query; anything not on the
// list is rejected outright. company_id is bound by this code, never by
// the AI or the client, so a spec can't reach across tenants even in
// principle — same isolation guarantee as every other query in this file.

type ViewFilter = { field: string; op: '>' | '<' | '>=' | '<=' | '=' | '!='; value: number | string };

type ViewSpec = {
  mode: 'single' | 'compare';
  columns: string[];
  sort: { field: string; direction: 'asc' | 'desc' } | null;
  limit: number;
  filters: ViewFilter[];                              // used when mode === 'single'
  groups: Array<{ label: string; filters: ViewFilter[] }>; // used when mode === 'compare'
};

// Every key here is a field the AI (and the client) is allowed to
// reference. `column` is the physical column name; `expr` is used instead
// for computed fields, and is written by US, never by the AI — so even a
// "computed" field can't be used to inject arbitrary SQL.
const QUERY_WHITELIST: Record<string, { expr: string; label: string; filterable: boolean }> = {
  name:            { expr: 'name',            label: 'Product name',        filterable: false },
  category:        { expr: 'category',        label: 'Category',            filterable: true },
  current_stock:   { expr: 'current_stock',    label: 'Stock on hand',       filterable: true },
  unit_price:      { expr: 'unit_price',       label: 'Sell price',          filterable: true },
  cost_price:      { expr: 'cost_price',       label: 'Cost price',          filterable: true },
  lead_time_days:  { expr: 'lead_time_days',   label: 'Vendor lead time (days)', filterable: true },
  demand_level:    { expr: 'demand_level',     label: 'Demand (units/day)',  filterable: true },
  demand_trend:    { expr: 'demand_trend',     label: 'Demand trend',        filterable: true },
  margin_pct:      { expr: "(CASE WHEN unit_price > 0 THEN (CASE WHEN cost_price > 0 THEN ROUND((unit_price - cost_price) / unit_price * 100, 1) ELSE 30 END) ELSE NULL END)", label: 'Margin %', filterable: true },
  margin_dollars:  { expr: '(CASE WHEN cost_price > 0 THEN ROUND(unit_price - cost_price, 2) ELSE ROUND(unit_price * 0.3, 2) END)', label: 'Margin $', filterable: true },
  days_of_stock:   { expr: '(CASE WHEN demand_level > 0.001 THEN ROUND(current_stock / demand_level, 1) ELSE NULL END)', label: 'Days of stock left', filterable: true },
};
const ALLOWED_OPS = new Set(['>', '<', '>=', '<=', '=', '!=']);
const MAX_VIEW_ROWS = 200;
const MAX_COMPARE_GROUPS = 3;

function whitelistDescriptionForPrompt(): string {
  return Object.entries(QUERY_WHITELIST)
    .map(([key, v]) => `- ${key}: ${v.label}${v.filterable ? '' : ' (not filterable/sortable)'}`)
    .join('\n');
}

// Shared by both single and compare mode — validates one filters array
// against the whitelist, dropping (never coercing) anything invalid.
function validateFilters(rawFilters: any): ViewFilter[] {
  const filters: ViewFilter[] = [];
  if (Array.isArray(rawFilters)) {
    for (const f of rawFilters) {
      if (!f || typeof f.field !== 'string' || !QUERY_WHITELIST[f.field] || !QUERY_WHITELIST[f.field].filterable) continue;
      if (typeof f.op !== 'string' || !ALLOWED_OPS.has(f.op)) continue;
      if (typeof f.value !== 'number' && typeof f.value !== 'string') continue;
      filters.push({ field: f.field, op: f.op, value: f.value });
    }
  }
  return filters;
}

// Rejects anything not on the whitelist — this is the actual security
// boundary, not the prompt. The prompt just makes the AI's job easier.
function validateViewSpec(raw: any): { spec: ViewSpec | null; error: string | null } {
  if (!raw || typeof raw !== 'object') return { spec: null, error: 'Could not understand that request.' };

  const columns = Array.isArray(raw.columns) ? raw.columns.filter((c: any) => typeof c === 'string') : [];
  const validColumns = columns.filter((c: string) => QUERY_WHITELIST[c]);
  if (validColumns.length === 0) return { spec: null, error: 'No recognized fields in that request — try naming specific product attributes like stock, price, or category.' };

  let sort: ViewSpec['sort'] = null;
  if (raw.sort && typeof raw.sort.field === 'string' && QUERY_WHITELIST[raw.sort.field]?.filterable) {
    const direction = raw.sort.direction === 'asc' ? 'asc' : 'desc';
    sort = { field: raw.sort.field, direction };
  }
  const limit = Math.min(MAX_VIEW_ROWS, Math.max(1, Number(raw.limit) || 50));

  if (raw.mode === 'compare') {
    const rawGroups = Array.isArray(raw.groups) ? raw.groups.slice(0, MAX_COMPARE_GROUPS) : [];
    const groups = rawGroups
      .filter((g: any) => g && typeof g.label === 'string')
      .map((g: any) => ({ label: g.label.trim().slice(0, 40) || 'Group', filters: validateFilters(g.filters) }));
    if (groups.length < 2) {
      return { spec: null, error: 'Could not split that into two groups to compare — try naming the two things you want side by side, e.g. "hardware vs software".' };
    }
    return { spec: { mode: 'compare', columns: validColumns, groups, sort, limit, filters: [] }, error: null };
  }

  const filters = validateFilters(raw.filters);
  return { spec: { mode: 'single', columns: validColumns, filters, sort, limit, groups: [] }, error: null };
}

// Turns a validated set of filters into a parameterized WHERE clause.
// company_id is bound here, by server code, always — the spec never
// carries it and never could, since it's not a whitelisted field.
function buildFilteredQuery(columns: string[], filters: ViewFilter[], sort: ViewSpec['sort'], limit: number, companyId: number): { sql: string; params: any[] } {
  const selectCols = columns.map((c) => `${QUERY_WHITELIST[c].expr} AS ${c}`).join(', ');
  const params: any[] = [companyId];
  let sql = `SELECT ${selectCols} FROM products WHERE company_id = ? AND archived = 0`;

  for (const f of filters) {
    sql += ` AND ${QUERY_WHITELIST[f.field].expr} ${f.op} ?`;
    params.push(f.value);
  }
  if (sort) {
    sql += ` ORDER BY ${QUERY_WHITELIST[sort.field].expr} ${sort.direction === 'asc' ? 'ASC' : 'DESC'}`;
    if (sort.field !== 'margin_dollars') sql += `, ${QUERY_WHITELIST.margin_dollars.expr} DESC`;
  }
  sql += ` LIMIT ?`;
  params.push(limit);

  return { sql, params };
}

async function callViewSpecLLM(env: Env, userRequest: string): Promise<any> {
  const prompt = `You turn a small business owner's plain-English report request into a JSON query spec over a PRODUCTS table.

AVAILABLE FIELDS (use ONLY these — never invent a field name):
${whitelistDescriptionForPrompt()}

There are two possible shapes to return. Pick whichever matches what the owner asked for.

1) A single filtered/sorted list — use this by default:
{
  "mode": "single",
  "columns": ["name", "current_stock", "days_of_stock"],
  "filters": [{ "field": "current_stock", "op": "<", "value": 10 }],
  "sort": { "field": "current_stock", "direction": "asc" },
  "limit": 50
}

2) A side-by-side COMPARISON of two or three groups — use this whenever the owner names two or more distinct sets of products they want to see separately, however they phrase it: "X vs Y", "X compared to Y", "my X and my Y", "split by category", "X versus Y". The connecting word doesn't matter ("vs", "and", "compared to") — what matters is whether the owner is naming distinct groups they want side by side, rather than describing several conditions on ONE list. "hardware and software" = two groups (compare mode). "items under 10 in stock and low margin" = one list with two conditions (single mode, two filters). Each group is just a label plus its own filters over the SAME fields:
{
  "mode": "compare",
  "columns": ["name", "demand_level"],
  "groups": [
    { "label": "Hardware", "filters": [{ "field": "category", "op": "!=", "value": "Software" }] },
    { "label": "Software", "filters": [{ "field": "category", "op": "=", "value": "Software" }] }
  ],
  "sort": { "field": "demand_level", "direction": "desc" },
  "limit": 10
}
For compare mode, "limit" applies PER GROUP (e.g. limit 10 means top 10 rows in each group, not 10 total) — keep it modest (5-15) so the two tables stay readable side by side. There is no single "hardware" category field — express "hardware" as everything that ISN'T "Software" (category != "Software"), unless the owner names specific categories, in which case list those categories explicitly instead.

Rules:
- "columns" must be a non-empty array of field keys from the list above. Always include "name" unless the owner clearly doesn't want it. Also always include ONE numeric field (demand_level, current_stock, unit_price, cost_price, margin_pct, margin_dollars, or days_of_stock) so the report can be charted — default to "demand_level" if the request doesn't make a metric obvious, unless the owner explicitly asked for only names/categories with no numbers.
- margin_pct and margin_dollars are NOT interchangeable. margin_pct is the percentage rate — many items may share the exact same margin_pct (e.g. everything without a scanned cost defaults to the same estimated rate), so sorting by it alone can rank low-value items above high-value ones. margin_dollars is the actual profit per unit sold. For any request about which items make the most money, the biggest profit, or similar dollar-focused phrasing ("makes me the most money", "most profitable", "highest profit"), use margin_dollars as the sort field, not margin_pct. Only use margin_pct when the owner specifically asks about rate/percentage (e.g. "which items have the best margin percentage").
- filters' op must be one of > < >= <= = !=.
- "sort" is optional.
- If the request doesn't map to these fields at all, return {"mode": "single", "columns": [], "filters": [], "sort": null, "limit": 50}.

Owner's request: "${userRequest}"`;
  const raw = await callGemmaText(env, prompt);
  const clean = raw.replace(/```json|```/g, '').trim();
  try { return JSON.parse(clean); } catch { return {}; }
}

// Executes a validated spec and returns a uniform shape: single mode
// returns { columns, rows }, compare mode returns { groups: [{ label,
// columns, rows }] } — the frontend branches on which key is present.
async function runViewSpec(env: Env, spec: ViewSpec, companyId: number) {
  const columnMeta = spec.columns.map((c) => ({ key: c, label: QUERY_WHITELIST[c].label }));

  if (spec.mode === 'compare') {
    const groups = [];
    for (const g of spec.groups) {
      const { sql, params } = buildFilteredQuery(spec.columns, g.filters, spec.sort, spec.limit, companyId);
      const { results } = await env.DB.prepare(sql).bind(...params).all();
      groups.push({ label: g.label, columns: columnMeta, rows: results ?? [] });
    }
    return { groups };
  }

  const { sql, params } = buildFilteredQuery(spec.columns, spec.filters, spec.sort, spec.limit, companyId);
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return { columns: columnMeta, rows: results ?? [] };
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

// ─── AI category classification ────────────────────────────────────────
// Every new product otherwise defaults to a flat "General" category,
// which makes the dashboard's category breakdown useless. This asks Gemma
// to pick a short, consistent category per product — reusing the
// company's existing categories where they genuinely fit (so "Cables"
// doesn't fragment into "Cable" / "Cabling" / "Wires" over time), and
// only inventing a new one when nothing fits.
async function categorizeProductsBatch(
  env: Env, companyId: number, items: { id: string | number; name: string }[]
): Promise<Record<string, string>> {
  if (items.length === 0) return {};

  const { results: existing } = await env.DB.prepare(
    `SELECT DISTINCT category FROM products WHERE company_id = ? AND category != 'General'`
  ).bind(companyId).all<{ category: string }>();
  const existingCategories = (existing ?? []).map((r) => r.category);

  const prompt = `Classify each product below into a short, consistent category (1-2 words) a shop owner would use to browse inventory — for example "Cables", "Peripherals", "Components", "Storage", "Networking", "Power", "Tools", "Accessories". Reuse one of these existing categories if it genuinely fits: ${existingCategories.length ? existingCategories.join(', ') : '(none yet)'}. Only invent a new category if nothing existing fits. Avoid "General" unless the product is truly miscellaneous.

Products:
${items.map((it) => `${it.id}: ${it.name}`).join('\n')}

Return ONLY a JSON object mapping each id (as a string key) to its category, no markdown, no explanation. Example: {"12": "Cables", "13": "Peripherals"}`;

  try {
    const raw = await callGemmaText(env, prompt);
    const clean = raw.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);
    return typeof parsed === 'object' && parsed ? parsed : {};
  } catch {
    return {}; // classification failure should never break product creation
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
          let category = body.category?.trim();
          if (!category) {
            const guesses = await categorizeProductsBatch(env, companyId, [{ id: 'new', name }]);
            category = guesses['new'] || 'General';
          }
          const created = await env.DB.prepare(
            `INSERT INTO products (company_id, name, normalized_name, category, unit_price, current_stock, lead_time_days)
             VALUES (?, ?, ?, ?, ?, 0, ?) RETURNING *`
          ).bind(companyId, name, normalizeText(name), category, body.unit_price || 0, body.lead_time_days || 3).first();
          productId = (created as any).id;
        } else if (productId) {
          // matching to an existing product — make sure it's actually this company's product
          const owned = await env.DB.prepare('SELECT id FROM products WHERE id = ? AND company_id = ?').bind(productId, companyId).first();
          if (!owned) return json({ error: 'product not found' }, 404);
        }

        if (!productId) return json({ error: 'product_id required for match' }, 400);
        await env.DB.prepare(
          'UPDATE receipt_items SET status = ?, resolved_product_id = ?, unit_price = COALESCE(?, unit_price) WHERE id = ?'
        ).bind('matched', productId, body.unit_price ?? null, itemId).run();
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

          const scannedPrice = Number(item.unit_price) > 0 ? Number(item.unit_price) : null;

          if (isPurchase) {
            const newStock = product.current_stock + item.qty;
            await env.DB.prepare(
              'UPDATE products SET current_stock = ?, cost_price = COALESCE(?, cost_price) WHERE id = ?'
            ).bind(newStock, scannedPrice, product.id).run();
          } else {
            const model = updateDemandModel(product, item.qty, saleDate);
            const newStock = Math.max(0, product.current_stock - item.qty);
            await env.DB.prepare(
              `UPDATE products SET current_stock = ?, demand_level = ?, demand_trend = ?, demand_variance = ?, last_sale_date = ?, unit_price = COALESCE(?, unit_price) WHERE id = ?`
            ).bind(newStock, model.demand_level, model.demand_trend, model.demand_variance, saleDate, scannedPrice, product.id).run();
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
        const b = await req.json() as { name: string; category?: string; unit_price?: number; cost_price?: number; current_stock?: number; lead_time_days?: number };
        if (!b.name?.trim()) return json({ error: 'name required' }, 400);
        let category = b.category?.trim();
        if (!category) {
          const guesses = await categorizeProductsBatch(env, companyId, [{ id: 'new', name: b.name.trim() }]);
          category = guesses['new'] || 'General';
        }
        const row = await env.DB.prepare(
          `INSERT INTO products (company_id, name, normalized_name, category, unit_price, cost_price, current_stock, lead_time_days)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
        ).bind(companyId, b.name.trim(), normalizeText(b.name), category, b.unit_price || 0, b.cost_price || 0, b.current_stock || 0, b.lead_time_days || 3).first();
        return json(row, 201);
      }

      // PUT /api/products/:id — edit stock / lead time / price / archive
      const productMatch = path.match(/^\/api\/products\/(\d+)$/);
      if (productMatch && req.method === 'PUT') {
        const id = Number(productMatch[1]);
        const b = await req.json() as Partial<{ name: string; category: string; unit_price: number; cost_price: number; current_stock: number; lead_time_days: number; archived: boolean }>;
        const existing = await env.DB.prepare('SELECT * FROM products WHERE id = ? AND company_id = ?').bind(id, companyId).first<ProductRow>();
        if (!existing) return json({ error: 'not found' }, 404);
        const name = b.name ?? existing.name;
        await env.DB.prepare(
          `UPDATE products SET name=?, normalized_name=?, category=?, unit_price=?, cost_price=?, current_stock=?, lead_time_days=?, archived=? WHERE id=? AND company_id=?`
        ).bind(
          name, normalizeText(name), b.category ?? existing.category, b.unit_price ?? existing.unit_price,
          b.cost_price ?? existing.cost_price, b.current_stock ?? existing.current_stock, b.lead_time_days ?? existing.lead_time_days,
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

            // POST /api/products/recategorize — batch re-classifies every
      // product currently sitting in the default "General" bucket.
      if (path === '/api/products/recategorize' && req.method === 'POST') {
        const { results } = await env.DB.prepare(
          `SELECT id, name FROM products WHERE company_id = ? AND archived = 0 AND category = 'General'`
        ).bind(companyId).all<{ id: number; name: string }>();
        const products = results ?? [];
        if (products.length === 0) return json({ updated: 0, total: 0 });

        const guesses = await categorizeProductsBatch(env, companyId, products.map((p) => ({ id: p.id, name: p.name })));
        let updated = 0;
        for (const p of products) {
          const category = guesses[String(p.id)];
          if (category && category !== 'General') {
            await env.DB.prepare('UPDATE products SET category = ? WHERE id = ? AND company_id = ?').bind(category, p.id, companyId).run();
            updated++;
          }
        }
        return json({ updated, total: products.length });
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

      // POST /api/views/generate — turns a plain-English report request
      // into a validated, whitelisted query and runs it immediately (not
      // saved). This is the "show me..." path — instant, disposable.
      // Supports two shapes: a single filtered list, or a side-by-side
      // comparison of 2-3 groups (e.g. "hardware vs software").
      if (path === '/api/views/generate' && req.method === 'POST') {
        const body = await req.json() as { request?: string };
        const userRequest = (body.request || '').trim().slice(0, 300);
        if (!userRequest) return json({ error: 'request required' }, 400);

        const rawSpec = await callViewSpecLLM(env, userRequest);
        const { spec, error } = validateViewSpec(rawSpec);
        if (error || !spec) return json({ error: error || 'Could not build a report from that.' }, 422);

        const result = await runViewSpec(env, spec, companyId);
        return json({ spec, ...result });
      }

      // POST /api/views — save a spec (already generated/validated) under a
      // name so it shows up as a permanent report the owner can rerun.
      if (path === '/api/views' && req.method === 'POST') {
        const body = await req.json() as { name?: string; spec?: any };
        const name = (body.name || '').trim().slice(0, 80);
        if (!name) return json({ error: 'name required' }, 400);
        const { spec, error } = validateViewSpec(body.spec);
        if (error || !spec) return json({ error: error || 'Invalid report spec' }, 422);

        const row = await env.DB.prepare(
          `INSERT INTO saved_views (company_id, name, spec_json) VALUES (?, ?, ?) RETURNING *`
        ).bind(companyId, name, JSON.stringify(spec)).first();
        return json(row, 201);
      }

      // GET /api/views — list this company's saved reports
      if (path === '/api/views' && req.method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT id, name, spec_json, created_at FROM saved_views WHERE company_id = ? ORDER BY created_at DESC'
        ).bind(companyId).all();
        return json(results ?? []);
      }

      // GET /api/views/:id/run — re-run a saved report against current data
      const viewRunMatch = path.match(/^\/api\/views\/(\d+)\/run$/);
      if (viewRunMatch && req.method === 'GET') {
        const id = Number(viewRunMatch[1]);
        const saved = await env.DB.prepare('SELECT * FROM saved_views WHERE id = ? AND company_id = ?').bind(id, companyId).first<any>();
        if (!saved) return json({ error: 'not found' }, 404);

        // Re-validate on every run, not just at save time — if the
        // whitelist ever changes, a stale saved spec degrades safely
        // instead of running raw.
        const { spec, error } = validateViewSpec(JSON.parse(saved.spec_json));
        if (error || !spec) return json({ error: 'This saved report is no longer valid — try recreating it.' }, 422);

        const result = await runViewSpec(env, spec, companyId);
        return json({ name: saved.name, ...result });
      }

      // DELETE /api/views/:id
      const viewDeleteMatch = path.match(/^\/api\/views\/(\d+)$/);
      if (viewDeleteMatch && req.method === 'DELETE') {
        const id = Number(viewDeleteMatch[1]);
        await env.DB.prepare('DELETE FROM saved_views WHERE id = ? AND company_id = ?').bind(id, companyId).run();
        return json({ ok: true });
      }

      // POST /api/assistant/chat — business-analyst chat over this
      // company's own data (sales, stock, categories, trends). Read-only:
      // nothing here is auto-applied to inventory, same "human confirms"
      // philosophy as auto-reorder.
      if (path === '/api/assistant/chat' && req.method === 'POST') {
        const body = await req.json() as { message?: string };
        const message = (body.message || '').trim().slice(0, 1000);
        if (!message) return json({ error: 'message required' }, 400);

        const { results: recent } = await env.DB.prepare(
          `SELECT role, message FROM assistant_messages WHERE company_id = ? ORDER BY id DESC LIMIT 8`
        ).bind(companyId).all<{ role: string; message: string }>();
        const history = (recent ?? []).reverse()
          .map((m) => `${m.role === 'user' ? 'Owner' : 'Assistant'}: ${m.message}`)
          .join('\n');

        const snapshot = await buildBusinessSnapshot(env, companyId);
        const snapshotText = formatSnapshotForPrompt(snapshot);
        const reply = await callAssistantLLM(env, snapshotText, history, message);

        await env.DB.prepare('INSERT INTO assistant_messages (company_id, role, message) VALUES (?, ?, ?)')
          .bind(companyId, 'user', message).run();
        await env.DB.prepare('INSERT INTO assistant_messages (company_id, role, message) VALUES (?, ?, ?)')
          .bind(companyId, 'assistant', reply).run();

        return json({ reply });
      }

            // GET /api/assistant/chat — load recent history for the chat panel
      if (path === '/api/assistant/chat' && req.method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT role, message, created_at FROM assistant_messages WHERE company_id = ? ORDER BY id DESC LIMIT 30`
        ).bind(companyId).all();
        return json((results ?? []).reverse());
      }

      // DELETE /api/assistant/chat — wipes this company's assistant history.
      // Called on every fresh page load/login so each session starts clean
      // instead of resuming an old conversation.
      if (path === '/api/assistant/chat' && req.method === 'DELETE') {
        await env.DB.prepare('DELETE FROM assistant_messages WHERE company_id = ?').bind(companyId).run();
        return json({ ok: true });
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
