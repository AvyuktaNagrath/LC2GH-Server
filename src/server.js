import Fastify from "fastify";
import cors from "@fastify/cors";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import { appOcto, instOcto } from "./lib/octo.js";
import { signJWT, newRefresh, verifyRefresh } from "./lib/tokens.js";


const db = new Database("data/app.sqlite");
db.pragma("journal_mode = WAL");
// Ensure base tables exist (idempotent)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// adjust the relative path to where 00_init.sql actually lives
const schemaPath = path.join(__dirname, "../sql/00_init.sql"); 
const schemaSql = fs.readFileSync(schemaPath, "utf8");
db.exec(schemaSql);


const app = Fastify({ logger: true });

// CORS (allow extension + localhost UI)
await app.register(cors, {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (origin.startsWith("chrome-extension://")) return cb(null, true);
    if (origin.startsWith("http://localhost")) return cb(null, true);
    cb(new Error("Not allowed"), false);
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "Idempotency-Key"]
});

const now = () => Date.now();

// Start: ONLY for extension. Requires nonce + redirect, persists redirect for callback.
app.get("/auth/github/start", async (req, reply) => {
  const { client = "ext", redirect = "", nonce = "" } = req.query;

  // Hard requirements for extension-only flow
  if (!nonce || !redirect) {
    return reply.code(400).send({ error: "invalid_request", message: "nonce and redirect are required" });
  }

  // Persist exact redirect so callback can do an exact-match redirect (no regex / no guessing)
  db.prepare(`
    INSERT INTO auth_flows (nonce, client, redirect, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(nonce) DO UPDATE SET
      client=excluded.client,
      redirect=excluded.redirect,
      created_at=excluded.created_at
  `).run(String(nonce), String(client), String(redirect), now());

  // Keep nonce in state (we ignore redirect from state later; DB is source of truth)
  const state = Buffer.from(JSON.stringify({ client, nonce })).toString("base64url");
  const url = `https://github.com/apps/${process.env.GITHUB_APP_SLUG}/installations/new?state=${state}`;
  return reply.redirect(url);
});



// Callback: ONLY redirect to the stored redirect for this nonce. Never return JSON tokens.
app.get("/auth/github/callback", async (req, reply) => {
  const { installation_id, state } = req.query;
  if (!installation_id) return reply.code(400).send({ error: "missing_installation_id" });

  // Pull nonce from state; we do NOT trust any redirect in state
  let nonce = "";
  try {
    const parsed = state ? JSON.parse(Buffer.from(state, "base64url").toString("utf8")) : {};
    nonce = parsed?.nonce ? String(parsed.nonce) : "";
  } catch (_) {}

  // Look up exact redirect saved at /start
  if (!nonce) return reply.code(400).send({ error: "invalid_request", message: "nonce missing; start this flow from the extension" });
  const rec = db.prepare("SELECT redirect FROM auth_flows WHERE nonce=?").get(nonce);
  if (!rec?.redirect) {
    return reply.code(400).send({ error: "missing_redirect", message: "Start this flow from the LC2GH extension" });
  }
  const storedRedirect = String(rec.redirect);

  // === (unchanged) GitHub app + user/repo persistence ===
  const octApp = appOcto();
  const { data: inst } = await octApp.request("GET /app/installations/{installation_id}", { installation_id });
  if (inst.account?.type !== "User") return reply.code(400).send({ error: "personal accounts only" });

  const userId = String(inst.account.id);
  const login = inst.account.login;
  const avatar = inst.account.avatar_url;

  db.prepare(
    "INSERT INTO users (id, login, avatar_url, created_at) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET login=excluded.login, avatar_url=excluded.avatar_url"
  ).run(userId, login, avatar, now());

  db.prepare(
    "INSERT INTO installations (installation_id, user_id, target_type, created_at) VALUES (?, ?, 'User', ?) " +
    "ON CONFLICT(installation_id) DO NOTHING"
  ).run(inst.id, userId, now());

  const io = instOcto(inst.id);
  const repos = await io.paginate(io.apps.listReposAccessibleToInstallation, { per_page: 100 });

  const insRepo = db.prepare(
    "INSERT INTO repos (id, installation_id, full_name, private) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET installation_id=excluded.installation_id, full_name=excluded.full_name, private=excluded.private"
  );
  for (const r of repos) insRepo.run(r.id, inst.id, r.full_name, r.private ? 1 : 0);

  let st = db.prepare("SELECT default_repo_id FROM settings WHERE user_id=?").get(userId);
  if (!st) {
    const first = repos[0];
    if (!first) return reply.code(400).send({ error: "no repositories granted to installation" });
    db.prepare("INSERT INTO settings (user_id, default_repo_id, updated_at) VALUES (?, ?, ?)").run(userId, first.id, now());
    st = { default_repo_id: first.id };
  }

  const { token: access, exp } = signJWT({ sub: userId, inst: inst.id, repo_id: st.default_repo_id, scopes: ["submit"] }, 45);
  const { raw: refreshRaw, hash } = await newRefresh();
  const rtId = nanoid();
  db.prepare("INSERT INTO refresh_tokens (id, user_id, ext_instance_id, hashed_token, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(rtId, userId, "pending", hash, now());

  // Cleanup the used nonce (best-effort)
  try { db.prepare("DELETE FROM auth_flows WHERE nonce=?").run(nonce); } catch {}

  // Always redirect to the exact stored redirect with tokens in the URL hash
  const u = new URL(storedRedirect);
  u.hash = `#jwt=${encodeURIComponent(access)}&refresh=${encodeURIComponent(`${rtId}:${refreshRaw}`)}&exp=${exp}`;
  return reply.redirect(u.toString());
});



// Refresh
app.post("/auth/refresh", async (req, reply) => {
  const { refresh_token, ext_instance_id } = req.body || {};
  if (!refresh_token) return reply.code(400).send({ error: "missing refresh_token" });
  const [id, raw] = String(refresh_token).split(":") || [];
  const row = db.prepare("SELECT * FROM refresh_tokens WHERE id=? AND revoked=0").get(id);
  if (!row) return reply.code(401).send({ error: "invalid refresh" });
  if (row.ext_instance_id !== "pending" && row.ext_instance_id !== ext_instance_id) {
    return reply.code(401).send({ error: "wrong device" });
  }
  const ok = await verifyRefresh(raw, row.hashed_token);
  if (!ok) return reply.code(401).send({ error: "invalid refresh" });

  if (row.ext_instance_id === "pending" && ext_instance_id) {
    db.prepare("UPDATE refresh_tokens SET ext_instance_id=? WHERE id=?").run(ext_instance_id, id);
  }
  db.prepare("UPDATE refresh_tokens SET revoked=1, last_used=? WHERE id=?").run(now(), id);

  const { raw: newRaw, hash: newHash } = await newRefresh();
  const newId = nanoid();
  db.prepare("INSERT INTO refresh_tokens (id, user_id, ext_instance_id, hashed_token, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(newId, row.user_id, ext_instance_id || row.ext_instance_id, newHash, now());

  const inst = db.prepare("SELECT installation_id FROM installations WHERE user_id=?").get(row.user_id);
  const st = db.prepare("SELECT default_repo_id FROM settings WHERE user_id=?").get(row.user_id);
  const { token: access, exp } = signJWT({ sub: row.user_id, inst: inst.installation_id, repo_id: st.default_repo_id, scopes: ["submit"] }, 45);

  return reply.send({ jwt: access, refresh_token: `${newId}:${newRaw}`, exp });
});

// Guard
function requireAuth(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) throw Object.assign(new Error("missing token"), { statusCode: 401 });
  try { return jwt.verify(t, process.env.JWT_SECRET); }
  catch { throw Object.assign(new Error("invalid token"), { statusCode: 401 }); }
}

// Settings
app.get("/v1/settings", async (req, reply) => {
  const c = requireAuth(req);
  const s = db.prepare(`
    SELECT u.login, u.avatar_url, s.default_repo_id, r.full_name
    FROM users u
    JOIN settings s ON s.user_id=u.id
    JOIN repos r ON r.id=s.default_repo_id
    WHERE u.id=?`).get(c.sub);
  return reply.send(s || {});
});

app.put("/v1/settings", async (req, reply) => {
  const c = requireAuth(req);
  const { default_repo_id } = req.body || {};
  if (!default_repo_id) return reply.code(400).send({ error: "missing default_repo_id" });
  const owned = db.prepare("SELECT 1 FROM repos WHERE id=? AND installation_id=?").get(default_repo_id, c.inst);
  if (!owned) return reply.code(403).send({ error: "repo not accessible by installation" });
  db.prepare("UPDATE settings SET default_repo_id=?, updated_at=? WHERE user_id=?").run(default_repo_id, now(), c.sub);
  return reply.send({ ok: true });
});

// Submissions stub (idempotency header enforced; commit worker later)
app.post("/v1/submissions", async (req, reply) => {
  const c = requireAuth(req);
  const idem = req.headers["idempotency-key"];
  if (!idem) return reply.code(400).send({ error: "Idempotency-Key required" });

  const { slug, title, language, code, url, timestamp } = req.body || {};
  if (!slug || !code) return reply.code(400).send({ error: "missing slug/code" });
  if (code.length > 200_000) return reply.code(413).send({ error: "code too large" });

  // TODO: enqueue commit job; for now accept
  return reply.code(202).send({ status: "queued" });
});

const port = Number(process.env.PORT || 8787);

try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`listening on ${port}`);
} catch (err) {
  app.log.error({ err }, "failed to start");
  process.exit(1);
}