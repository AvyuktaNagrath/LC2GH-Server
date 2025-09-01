import Fastify from "fastify";
import cors from "@fastify/cors";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import { appOcto, instOcto } from "./lib/octo.js";
import { signJWT, newRefresh, verifyRefresh } from "./lib/tokens.js";
import crypto from "node:crypto";
import { extFor } from "./lib/ext.js";
import { upsertFile } from "./lib/commit.js";


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
    if (origin.startsWith("https://leetcode.com")) return cb(null, true);
    if (origin.startsWith("https://leetcode.cn")) return cb(null, true);
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

  // Ensure only ONE installation per user
  db.prepare("DELETE FROM installations WHERE user_id=?").run(userId);

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

  const inst = db.prepare(`
    SELECT installation_id
    FROM installations
    WHERE user_id=?
    ORDER BY created_at DESC
    LIMIT 1
  `).get(row.user_id);
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

// Submissions: commit to repo (idempotent via code_sha soft-dedupe)
app.post("/v1/submissions", async (req, reply) => {
  const c = requireAuth(req);
  if (!Array.isArray(c.scopes) || !c.scopes.includes("submit")) {
    return reply.code(403).send({ error: "forbidden", message: "missing submit scope" });
  }

  const idem = req.headers["idempotency-key"];
  if (!idem) return reply.code(400).send({ error: "Idempotency-Key required" });

  const { slug, title, language, code, url, timestamp, difficulty, tags } = req.body || {};
  if (!slug || !code) return reply.code(400).send({ error: "missing slug/code" });
  if (code.length > 200_000) return reply.code(413).send({ error: "code too large" });

  const codeSha = crypto.createHash("sha256").update(code, "utf8").digest("hex");
  const existing = db
    .prepare("SELECT id FROM submissions WHERE user_id=? AND code_sha=? LIMIT 1")
    .get(c.sub, codeSha);
  if (existing) {
    return reply.code(200).send({ status: "duplicate", submission_id: existing.id });
  }

  const st = db.prepare("SELECT default_repo_id, path_template FROM settings WHERE user_id=?").get(c.sub);
  if (!st) return reply.code(400).send({ error: "no settings", message: "no default repo configured" });

  let repoRow = db.prepare("SELECT full_name, installation_id FROM repos WHERE id=?").get(st.default_repo_id);
  if (!repoRow) return reply.code(400).send({ error: "repo not found for default_repo_id" });

  // Lazy resync if mismatch
  if (repoRow.installation_id !== c.inst) {
    const ioSync = instOcto(c.inst);
    const fresh = await ioSync.paginate(ioSync.apps.listReposAccessibleToInstallation, { per_page: 100 });

    const up = db.prepare(
      "INSERT INTO repos (id, installation_id, full_name, private) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(id) DO UPDATE SET installation_id=excluded.installation_id, full_name=excluded.full_name, private=excluded.private"
    );
    for (const r of fresh) up.run(r.id, c.inst, r.full_name, r.private ? 1 : 0);

    repoRow = db.prepare("SELECT full_name, installation_id FROM repos WHERE id=?").get(st.default_repo_id);
    if (!repoRow) return reply.code(400).send({ error: "repo not found after sync" });
  }

  if (repoRow.installation_id !== c.inst) {
    return reply.code(403).send({ error: "repo not accessible by installation" });
  }

  const [owner, repo] = String(repoRow.full_name).split("/");
  if (!owner || !repo) return reply.code(500).send({ error: "bad repo full_name" });

  const tpl = st.path_template || "problems/{primary}/{slug}";
  const tsIso = typeof timestamp === "string" && timestamp ? timestamp : new Date().toISOString();
  const dateStr = tsIso.slice(0, 10);
  const tsCompact = tsIso.replace(/[-:TZ.]/g, "").slice(0, 15);
  const primary = (difficulty || "").toLowerCase() || "unknown";
  const langExt = extFor(language || "");
  const fill = (s) =>
    s.replaceAll("{slug}", slug)
      .replaceAll("{primary}", primary)
      .replaceAll("{date}", dateStr)
      .replaceAll("{ts}", tsCompact)
      .replaceAll("{lang_ext}", langExt);

  let relPath = fill(tpl);
  const last = relPath.split("/").pop() || "";
  if (!last.includes(".")) {
    if (relPath && !relPath.endsWith("/")) relPath += "/";
    relPath += `solution.${langExt || "txt"}`;
  }

  try {
    const io = instOcto(c.inst);
    const message = `feat(lc): ${slug} — ${title || slug}${language ? ` [${language}]` : ""}`;
    const commitSha = await upsertFile(io, owner, repo, relPath, code, message);

    // 👉 also write a README.md alongside the solution
    const readmePath = relPath.replace(/[^/]+$/, "README.md");
    const readmeContent = `# ${title || slug}

    - **Slug:** ${slug}
    - **Difficulty:** ${difficulty || "—"}
    - **Language:** ${language || "—"}
    - **Source:** ${url || ""}
    - **Captured:** ${tsIso}

    ## Code

    \`\`\`${language || ""}
    ${code.slice(0, 2000)} 
    \`\`\`
    `;

    await upsertFile(io, owner, repo, readmePath, readmeContent, message);
    

    const submissionId = nanoid();
    db.prepare(
      `INSERT INTO submissions
       (id, user_id, slug, language, url, ts, code_sha, size, difficulty, tags_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      submissionId,
      c.sub,
      slug,
      language || null,
      url || null,
      tsIso,
      codeSha,
      code.length,
      difficulty || null,
      tags ? JSON.stringify(tags) : null,
      now()
    );

    return reply.code(201).send({
      status: "committed",
      repo: repoRow.full_name,
      path: relPath,
      commit_sha: commitSha,
      submission_id: submissionId
    });
  } catch (e) {
    req.log.error({ err: e }, "commit failed");
    const msg = e?.message || "commit failed";
    const status = e?.status;
    if (status === 403) return reply.code(403).send({ error: "forbidden", message: msg });
    if (status === 404) return reply.code(404).send({ error: "not_found", message: msg });
    return reply.code(502).send({ error: "github_error", message: msg });
  }
});



const port = Number(process.env.PORT || 8787);

try {
  const oct = appOcto();
  const { data: appInfo } = await oct.request("GET /app");
  app.log.info({ appId: appInfo.id, slug: appInfo.slug, name: appInfo.name }, "GitHub App credentials loaded");
} catch (e) {
  app.log.error({ err: e }, "Failed to identify GitHub App");
}

try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`listening on ${port}`);
} catch (err) {
  app.log.error({ err }, "failed to start");
  process.exit(1);
}