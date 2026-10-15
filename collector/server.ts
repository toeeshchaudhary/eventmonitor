#!/usr/bin/env bun
/**
 * EventMonitor collector.
 *
 * Receives batches from agents on event machines we own, stores them THREE ways:
 *   1. SQLite (events.db)         - fast queries for the dashboard
 *   2. flat JSONL (dump/)         - greppable, survives DB loss
 *   3. JPEG files (blobs/)        - screenshots as real files
 *
 *   bun run server.ts              # start
 *   bun run server.ts --gen-token  # print a fresh machine token
 *
 * Auth: agents sign each batch with HMAC-SHA256 using their machine token, sent
 * as X-Signature, alongside X-Machine-Id + X-Token. Admin routes need
 * X-Admin-Token (or ?token=). Nothing is served without a token.
 *
 * Enrollment: POST /enroll with X-Enroll-Secret lets a lab machine get its own
 * token instead of you typing one per box. Turn it off once provisioning is done.
 */

import { Database } from "bun:sqlite";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { networkInterfaces } from "node:os";
import { join, resolve } from "node:path";

const ROOT = import.meta.dir;
const CONFIG_PATH = join(ROOT, "collector.json");

// token helper: `bun run server.ts --gen-token`
if (process.argv.includes("--gen-token")) {
  console.log(randomUUID().replace(/-/g, ""));
  process.exit(0);
}

type MachineCfg = { token: string; label?: string; enrolledAt?: string };
type Config = {
  host: string;
  port: number;
  dataDir: string;
  adminToken: string;
  retentionDays: number;
  maxBatchBytes: number;
  dumpJsonl?: boolean;
  enroll?: { enabled: boolean; secret: string };
  machines?: Record<string, MachineCfg>;
};

function loadConfig(): Config {
  if (!existsSync(CONFIG_PATH)) {
    const fresh: Config = {
      host: "0.0.0.0",
      port: 8787,
      dataDir: "./data",
      adminToken: randomUUID().replace(/-/g, ""),
      retentionDays: 7,
      maxBatchBytes: 8 * 1024 * 1024,
      dumpJsonl: true,
      enroll: { enabled: false, secret: "" },
      machines: {},
    };
    writeFileSync(CONFIG_PATH, JSON.stringify(fresh, null, 2));
    console.log(`wrote ${CONFIG_PATH} - configure it, then restart (or use Setup-EventMonitor.ps1)`);
    process.exit(0);
  }
  // PowerShell 5.1's `Set-Content -Encoding UTF8` writes a BOM, which JSON.parse
  // rejects outright. Strip it rather than relying on the writer.
  const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8").replace(/^\uFEFF/, "")) as Config;
  cfg.dataDir = resolve(ROOT, cfg.dataDir);
  cfg.machines = cfg.machines ?? {};
  cfg.retentionDays = cfg.retentionDays ?? 7;
  cfg.maxBatchBytes = cfg.maxBatchBytes ?? 8 * 1024 * 1024;
  cfg.dumpJsonl = cfg.dumpJsonl !== false;
  return cfg;
}

const cfg = loadConfig();

if (cfg.adminToken.includes("CHANGE-ME") || cfg.adminToken.length < 16) {
  console.error("refusing to start: set a real adminToken in collector.json (>=16 chars)");
  process.exit(1);
}

mkdirSync(cfg.dataDir, { recursive: true });
const BLOBS = join(cfg.dataDir, "blobs");
const DUMP = join(cfg.dataDir, "dump");
mkdirSync(BLOBS, { recursive: true });
mkdirSync(DUMP, { recursive: true });

// --- machine registry -------------------------------------------------------
// collector.json seeds the registry; /enroll adds to it at runtime. The registry
// is the authoritative source for tokens, so re-enrollment survives restarts.

const REGISTRY_PATH = join(cfg.dataDir, "registry.json");
const registry: Record<string, MachineCfg> = {};

for (const [id, m] of Object.entries(cfg.machines)) {
  if (m?.token && !m.token.includes("CHANGE-ME")) registry[id] = { ...m };
}
if (existsSync(REGISTRY_PATH)) {
  try {
    for (const [id, m] of Object.entries(JSON.parse(readFileSync(REGISTRY_PATH, "utf8").replace(/^\uFEFF/, "")) as Record<string, MachineCfg>)) {
      if (m?.token) registry[id] = { ...registry[id], ...m };
    }
  } catch (err) {
    console.error("registry.json unreadable, starting from collector.json:", err);
  }
}

function saveRegistry(): void {
  writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
}

// --- storage ----------------------------------------------------------------

const db = new Database(join(cfg.dataDir, "events.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;

  CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id TEXT NOT NULL,
    sid        TEXT,
    ts         TEXT NOT NULL,
    type       TEXT NOT NULL,
    process    TEXT,
    title      TEXT,
    data       TEXT NOT NULL,
    blob       TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_events_machine_ts ON events (machine_id, ts);
  CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);

  CREATE TABLE IF NOT EXISTS machines (
    id         TEXT PRIMARY KEY,
    label      TEXT,
    station    TEXT,
    attendee   TEXT,
    first_seen TEXT,
    last_seen  TEXT,
    last_ip    TEXT,
    n_events   INTEGER NOT NULL DEFAULT 0
  );
`);

// migrate databases created before station/attendee existed
const machineCols = (db.query(`PRAGMA table_info(machines)`).all() as { name: string }[]).map((c) => c.name);
if (!machineCols.includes("station")) db.exec(`ALTER TABLE machines ADD COLUMN station TEXT`);
if (!machineCols.includes("attendee")) db.exec(`ALTER TABLE machines ADD COLUMN attendee TEXT`);

const insertEvent = db.prepare(
  `INSERT INTO events (machine_id, sid, ts, type, process, title, data, blob)
   VALUES ($machine_id, $sid, $ts, $type, $process, $title, $data, $blob)`,
);
const touchMachine = db.prepare(
  `INSERT INTO machines (id, label, station, attendee, first_seen, last_seen, last_ip, n_events)
   VALUES ($id, $label, $station, $attendee, $now, $now, $ip, $n)
   ON CONFLICT(id) DO UPDATE SET
     last_seen = $now,
     last_ip = $ip,
     n_events = n_events + $n,
     station = COALESCE($station, station),
     attendee = COALESCE($attendee, attendee)`,
);

// Flat-file mirror of everything, one line per event, one directory per machine.
// This is the "storage file" that survives losing events.db.
function appendDump(machineId: string, ts: string, record: Record<string, unknown>): void {
  if (!cfg.dumpJsonl) return;
  try {
    const dir = join(DUMP, machineId);
    mkdirSync(dir, { recursive: true });
    const day = ts.slice(0, 10) || new Date().toISOString().slice(0, 10);
    appendFileSync(join(dir, `${day}.jsonl`), JSON.stringify(record) + "\n");
  } catch (err) {
    console.error("dump append failed:", err);
  }
}

// --- helpers ----------------------------------------------------------------

const SAFE_ID = /^[A-Za-z0-9._-]+$/;

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function isAdmin(req: Request, url: URL): boolean {
  const token = req.headers.get("x-admin-token") ?? url.searchParams.get("token") ?? "";
  return safeEqual(token, cfg.adminToken);
}

// --- enrollment -------------------------------------------------------------

async function handleEnroll(req: Request): Promise<Response> {
  if (!cfg.enroll?.enabled) return json({ ok: false, error: "enrollment disabled" }, 403);

  const secret = req.headers.get("x-enroll-secret") ?? "";
  if (!cfg.enroll.secret || !safeEqual(secret, cfg.enroll.secret)) {
    return json({ ok: false, error: "bad enroll secret" }, 401);
  }

  let payload: { machineId?: string; label?: string };
  try {
    payload = (await req.json()) as { machineId?: string; label?: string };
  } catch {
    return json({ ok: false, error: "invalid json" }, 400);
  }

  const machineId = String(payload.machineId ?? "");
  if (!SAFE_ID.test(machineId)) return json({ ok: false, error: "bad machine id" }, 400);

  // idempotent: re-provisioning a box returns the token it already has
  const existing = registry[machineId];
  if (existing?.token) {
    console.log(`enroll: ${machineId} re-provisioned (existing token)`);
    return json({ ok: true, machineId, token: existing.token, reused: true });
  }

  const token = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
  registry[machineId] = {
    token,
    label: typeof payload.label === "string" && payload.label ? payload.label : machineId,
    enrolledAt: new Date().toISOString(),
  };
  saveRegistry();
  console.log(`enroll: ${machineId} registered (${Object.keys(registry).length} total)`);
  return json({ ok: true, machineId, token, reused: false });
}

// --- ingest -----------------------------------------------------------------

async function handleIngest(req: Request): Promise<Response> {
  const machineId = req.headers.get("x-machine-id") ?? "";
  if (!SAFE_ID.test(machineId)) return json({ ok: false, error: "bad machine id" }, 400);

  const entry = registry[machineId];
  const token = req.headers.get("x-token") ?? "";
  if (!entry?.token || !safeEqual(token, entry.token)) {
    return json({ ok: false, error: "unauthorized" }, 401);
  }

  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > cfg.maxBatchBytes) return json({ ok: false, error: "batch too large" }, 413);

  const raw = await req.text();
  if (raw.length > cfg.maxBatchBytes) return json({ ok: false, error: "batch too large" }, 413);

  // Integrity: the batch must be signed with the machine token. A sniffer on the
  // event LAN can read cleartext HTTP, but cannot forge or alter a batch.
  const signature = req.headers.get("x-signature") ?? "";
  const expected = createHmac("sha256", entry.token).update(raw).digest("hex");
  if (!signature || !safeEqual(signature, expected)) {
    console.warn(`ingest: bad signature from ${machineId}`);
    return json({ ok: false, error: "bad signature" }, 401);
  }

  let payload: { events?: unknown[] };
  try {
    payload = JSON.parse(raw) as { events?: unknown[] };
  } catch {
    return json({ ok: false, error: "invalid json" }, 400);
  }
  const events = Array.isArray(payload.events) ? payload.events : null;
  if (!events) return json({ ok: false, error: "events[] required" }, 400);
  if (events.length === 0) return json({ ok: true, stored: 0 });

  const ip = req.headers.get("x-forwarded-for") ?? "local";
  const now = new Date().toISOString();
  let stored = 0;
  const shotDir = join(BLOBS, machineId);

  const run = db.transaction((rows: Record<string, unknown>[]) => {
    let latestStation: string | null = null;
    let latestAttendee: string | null = null;
    for (const raw of rows) {
      if (!raw || typeof raw !== "object") continue;
      const ev = { ...(raw as Record<string, unknown>) };

      let blobRel: string | null = null;
      if (ev.type === "shot" && typeof ev.b64 === "string" && ev.b64.length > 0) {
        try {
          mkdirSync(shotDir, { recursive: true });
          const name = `${(ev.ts as string) || now}-${randomUUID().slice(0, 8)}.jpg`.replace(/[^A-Za-z0-9._-]/g, "-");
          writeFileSync(join(shotDir, name), Buffer.from(ev.b64, "base64"));
          blobRel = `${machineId}/${name}`;
        } catch (err) {
          console.error("blob write failed:", err);
        }
      }
      delete ev.b64;

      const ts = typeof ev.ts === "string" && ev.ts ? ev.ts : now;
      const type = typeof ev.type === "string" && ev.type ? ev.type : "unknown";

      // last non-empty wins: this is how the console knows who/where a machine is
      if (typeof ev.station === "string" && ev.station) latestStation = ev.station;
      if (typeof ev.attendee === "string" && ev.attendee) latestAttendee = ev.attendee;

      insertEvent.run({
        $machine_id: machineId,
        $sid: typeof ev.sid === "string" ? ev.sid : null,
        $ts: ts,
        $type: type,
        $process: typeof ev.process === "string" ? ev.process : null,
        $title: typeof ev.title === "string" ? ev.title : null,
        $data: JSON.stringify(ev),
        $blob: blobRel,
      });

      appendDump(machineId, ts, {
        machine: machineId,
        sid: ev.sid ?? null,
        ts,
        type,
        process: ev.process ?? null,
        title: ev.title ?? null,
        blob: blobRel,
        ...ev,
      });
      stored++;
    }
    touchMachine.run({
      $id: machineId,
      $label: registry[machineId]?.label ?? null,
      $station: latestStation,
      $attendee: latestAttendee,
      $now: now,
      $ip: ip,
      $n: stored,
    });
  });

  try {
    run(events as Record<string, unknown>[]);
  } catch (err) {
    console.error("ingest failed:", err);
    return json({ ok: false, error: "storage error" }, 500);
  }

  console.log(`${now} <- ${machineId} ${stored} event(s) from ${ip}`);
  return json({ ok: true, stored });
}

// --- read APIs --------------------------------------------------------------

function buildFilter(url: URL) {
  const clauses: string[] = [];
  const params: Record<string, string | number> = {};
  const machine = url.searchParams.get("machine");
  const type = url.searchParams.get("type");
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  if (machine) { clauses.push("machine_id = $machine"); params.$machine = machine; }
  if (type) { clauses.push("type = $type"); params.$type = type; }
  if (from) { clauses.push("ts >= $from"); params.$from = from; }
  if (to) { clauses.push("ts <= $to"); params.$to = to; }
  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

function handleEvents(url: URL): Response {
  const { where, params } = buildFilter(url);
  const limit = Math.min(Number(url.searchParams.get("limit") ?? 500) || 500, 5000);
  const offset = Number(url.searchParams.get("offset") ?? 0) || 0;
  params.$limit = limit;
  params.$offset = offset;

  const rows = db
    .query(
      `SELECT id, machine_id, sid, ts, type, process, title, data, blob
       FROM events ${where} ORDER BY ts ASC, id ASC LIMIT $limit OFFSET $offset`,
    )
    .all(params as never) as Record<string, unknown>[];

  const items = rows.map((r) => ({
    id: r.id,
    machine: r.machine_id,
    sid: r.sid,
    ts: r.ts,
    type: r.type,
    process: r.process,
    title: r.title,
    blob: r.blob,
    data: JSON.parse(r.data as string),
  }));
  return json({ ok: true, count: items.length, items });
}

function handleMachines(): Response {
  const rows = db
    .query(`SELECT id, label, station, attendee, first_seen, last_seen, last_ip, n_events FROM machines ORDER BY id`)
    .all() as Record<string, unknown>[];

  const byId = new Map(rows.map((r) => [String(r.id), r]));
  const enrolled = Object.keys(registry).sort().map((id) => ({
    id,
    label: registry[id]?.label ?? null,
    enrolledAt: registry[id]?.enrolledAt ?? null,
    station: (byId.get(id)?.station as string) ?? null,
    attendee: (byId.get(id)?.attendee as string) ?? null,
  }));
  return json({ ok: true, items: rows, enrolled });
}

function handleStats(url: URL): Response {
  const { where, params } = buildFilter(url);
  const byType = db
    .query(`SELECT type, COUNT(*) AS n FROM events ${where} GROUP BY type ORDER BY n DESC`)
    .all(params as never);
  const span = db.query(`SELECT MIN(ts) AS first_event, MAX(ts) AS last_event FROM events`).get();
  return json({
    ok: true,
    byType,
    span,
    storage: {
      dataDir: cfg.dataDir,
      dumpDir: DUMP,
      blobDir: BLOBS,
      dumpJsonl: cfg.dumpJsonl,
      retentionDays: cfg.retentionDays,
    },
  });
}

function handleExport(url: URL): Response {
  const { where, params } = buildFilter(url);
  const rows = db
    .query(`SELECT machine_id, sid, ts, type, process, title, data, blob FROM events ${where} ORDER BY ts ASC, id ASC`)
    .all(params as never) as Record<string, unknown>[];
  const lines = rows.map((r) =>
    JSON.stringify({
      machine: r.machine_id,
      sid: r.sid,
      ts: r.ts,
      type: r.type,
      process: r.process,
      title: r.title,
      blob: r.blob,
      ...JSON.parse(r.data as string),
    }),
  );
  const name = `eventmon-export-${new Date().toISOString().slice(0, 10)}.jsonl`;
  return new Response(lines.join("\n"), {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "content-disposition": `attachment; filename="${name}"`,
    },
  });
}

function handleBlob(url: URL): Response {
  const rel = decodeURIComponent(url.pathname.replace(/^\/blob\//, ""));
  const parts = rel.split("/");
  if (parts.length !== 2 || !parts.every((p) => SAFE_ID.test(p) && p !== "." && p !== "..")) {
    return json({ ok: false, error: "bad blob path" }, 400);
  }
  const full = join(BLOBS, parts[0], parts[1]);
  if (!existsSync(full)) return json({ ok: false, error: "not found" }, 404);
  return new Response(Bun.file(full), {
    headers: { "content-type": "image/jpeg", "cache-control": "private, max-age=300" },
  });
}

// --- retention --------------------------------------------------------------

function prune(): void {
  const cutoffMs = Date.now() - cfg.retentionDays * 86400_000;
  const cutoff = new Date(cutoffMs).toISOString();
  const res = db.prepare(`DELETE FROM events WHERE ts < $cutoff`).run({ $cutoff: cutoff });

  // flat dumps: filename carries the day, so compare on that
  const cutoffDay = new Date(cutoffMs).toISOString().slice(0, 10);
  let dumps = 0;
  for (const machine of readdirSync(DUMP, { withFileTypes: true })) {
    if (!machine.isDirectory()) continue;
    const dir = join(DUMP, machine.name);
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".jsonl")) continue;
      if (f.slice(0, 10) < cutoffDay) { unlinkSync(join(dir, f)); dumps++; }
    }
  }

  let blobs = 0;
  for (const machine of readdirSync(BLOBS, { withFileTypes: true })) {
    if (!machine.isDirectory()) continue;
    const dir = join(BLOBS, machine.name);
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      try {
        if (statSync(p).mtimeMs < cutoffMs) { unlinkSync(p); blobs++; }
      } catch {}
    }
  }

  console.log(`prune(${cfg.retentionDays}d): ${res.changes} event(s), ${dumps} dump file(s), ${blobs} blob(s)`);
}

// --- dashboard --------------------------------------------------------------

function handleDashboard(): Response {
  const p = join(ROOT, "public", "index.html");
  if (!existsSync(p)) return new Response("dashboard missing", { status: 500 });
  return new Response(Bun.file(p), { headers: { "content-type": "text/html; charset=utf-8" } });
}

// --- server -----------------------------------------------------------------

function lanAddresses(): string[] {
  const out: string[] = [];
  for (const list of Object.values(networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === "IPv4" && !ni.internal) out.push(ni.address);
    }
  }
  return out;
}

const server = Bun.serve({
  hostname: cfg.host,
  port: cfg.port,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/" || path === "/index.html") return handleDashboard();
    if (path === "/health") {
      return json({ ok: true, machines: Object.keys(registry).length, enroll: !!cfg.enroll?.enabled });
    }
    if (path === "/enroll" && req.method === "POST") return handleEnroll(req);
    if (path === "/ingest" && req.method === "POST") return handleIngest(req);

    if (path.startsWith("/blob/")) {
      if (!isAdmin(req, url)) return json({ ok: false, error: "unauthorized" }, 401);
      return handleBlob(url);
    }

    if (path.startsWith("/api/")) {
      if (!isAdmin(req, url)) return json({ ok: false, error: "unauthorized" }, 401);
      if (path === "/api/machines") return handleMachines();
      if (path === "/api/events") return handleEvents(url);
      if (path === "/api/stats") return handleStats(url);
      if (path === "/api/export") return handleExport(url);
      return json({ ok: false, error: "unknown endpoint" }, 404);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
});

setInterval(prune, 3600_000);

console.log(`EventMonitor collector on http://${cfg.host}:${server.port}`);
console.log(`  storage    : ${cfg.dataDir}`);
console.log(`               events.db + dump/<machine>/<day>.jsonl + blobs/<machine>/*.jpg`);
console.log(`  machines   : ${Object.keys(registry).length} enrolled`);
console.log(`  enrollment : ${cfg.enroll?.enabled ? "OPEN (turn off when provisioning is done)" : "closed"}`);
console.log(`  retention  : ${cfg.retentionDays} days`);
for (const ip of lanAddresses()) console.log(`  dashboard  : http://${ip}:${server.port}/`);
