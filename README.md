# Auto Stockers

AI-powered restocking assistant — scans sales receipts, matches line items
against your inventory without any POS integration, and computes per-item
adaptive reorder points instead of one fixed threshold for everything.

## What makes it different from a normal reorder-point calculator

1. **Receipt understanding without a catalog.** A vision model (Gemma, via
   the Gemini API) reads a photo of a receipt into structured lines. Since
   there's no barcode/SKU lookup, each line is fuzzy-matched (bigram Dice
   similarity) against your existing product names, and anything below a
   confidence threshold is flagged for a human to confirm or turn into a
   new product. That matching step is the actual hard problem — a
   POS-integrated system never has to solve it, because it already knows
   its own SKUs.

2. **Per-item adaptive reorder points.** Each product tracks its own demand
   *level* and *trend* using Holt's linear method (double exponential
   smoothing), updated after every confirmed sale, plus a running estimate
   of demand variance for safety stock. The reorder point is recomputed
   per item from that model — a trending-up item and a flat item get
   different treatment automatically, instead of "reorder at 10 units"
   for the whole store.

3. **AI writes the human-readable part.** The forecasting math is
   deterministic and auditable (you can see the reorder point, target
   stock, and reasoning for every item). A text model is only used at the
   very end, to turn that math into a short plain-English restock note —
   perception (vision) and communication (text) are the two places AI
   actually earns its place; the core logic isn't a black box.

## Stack

Cloudflare Workers + D1, static HTML/JS frontend served from the same
Worker via Workers Assets — same pattern as your other client sites, just
without a separate Pages project.

## First-time setup

```bash
npm install

# Create the D1 database
wrangler d1 create auto-stockers-db
# Copy the database_id it prints into wrangler.toml (REPLACE_WITH_YOUR_D1_DATABASE_ID)

# Load the schema
npm run db:init

# Set secrets (same GEMINI_API_KEY you already use on your other sites)
wrangler secret put ADMIN_PASSWORD
wrangler secret put GEMINI_API_KEY

# Deploy once by hand to sanity-check it
wrangler deploy
```

Open the deployed URL, log in with the ADMIN_PASSWORD you set, and you're in.

## Auto-deploy on push

`.github/workflows/deploy.yml` deploys on every push to `main`. In your
GitHub repo settings → Secrets and variables → Actions, add:

- `CLOUDFLARE_API_TOKEN` — a token with Workers Scripts:Edit + D1:Edit permissions
- `CLOUDFLARE_ACCOUNT_ID` — from the Cloudflare dashboard sidebar

Push to `main` and the Action redeploys automatically — same flow as
`wrangler deploy`, just triggered by git instead of you running it by hand.

## Using it

1. **Scan Receipt tab** — upload/photograph a receipt. Review the matched
   lines, confirm or create new products, then hit "Confirm & log sales" —
   this is what actually decrements stock and updates the demand model.
2. **Inventory tab** — see current stock, demand trend, and reorder status
   per item. Add products manually here too if you don't want to wait for
   a receipt.
3. **Recommendations tab** — "Generate AI note" computes reorder points for
   every product and asks the model to draft a short summary of what to
   order first.

## Local dev

```bash
npm run dev
```

Wrangler will spin up a local D1 instance — run `npm run db:init:local`
first to load the schema into it.
