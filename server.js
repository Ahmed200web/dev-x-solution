require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const { WebSocketServer } = require("ws");
const { v4: uuidv4 } = require("uuid");
const http       = require("http");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const morgan     = require("morgan");

const app    = express();
const server = http.createServer(app);

// ════════════════════════════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════════════════════════════
const JWT_SECRET  = process.env.JWT_SECRET  || "dex-x-secret-CHANGE-ME";
const JWT_REFRESH = process.env.JWT_REFRESH || "dex-x-refresh-CHANGE-ME";
const PORT        = process.env.PORT        || 8080;
const NODE_ENV    = process.env.NODE_ENV    || "development";

// ════════════════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════
app.set("trust proxy", 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false,
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true,
}));

app.use(express.json({ limit: "1mb" }));
app.use(morgan(NODE_ENV === "production" ? "combined" : "dev"));

// ─── Rate Limiters ──────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many auth attempts, try again in 15 minutes." },
});

app.use(globalLimiter);

// ════════════════════════════════════════════════════════════════════════════
// IN-MEMORY DATABASE
// ════════════════════════════════════════════════════════════════════════════
const db = {
  users: [
    {
      id: "user-001",
      name: "Admin",
      email: "admin@dex-x.io",
      password: bcrypt.hashSync("admin123", 10),
      role: "admin",
      avatar: null,
      createdAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
    },
  ],

  // refresh token store: { token -> { userId, expiresAt } }
  refreshTokens: {},

  logs: [],

  alerts: [
    { id: uuidv4(), level: "CRITICAL", title: "SQL Injection Attempt", message: "Pattern detected on /api/v2/auth — auto-blocked", resolved: false, createdAt: new Date(Date.now() - 5 * 60000).toISOString() },
    { id: uuidv4(), level: "WARNING",  title: "High RAM Usage",       message: "Server RAM exceeded 80% for 10 minutes",          resolved: false, createdAt: new Date(Date.now() - 12 * 60000).toISOString() },
    { id: uuidv4(), level: "INFO",     title: "SSL Certificate",      message: "Auto-renewed successfully, valid for 90 days",    resolved: true,  createdAt: new Date(Date.now() - 60 * 60000).toISOString() },
  ],

  // Historical metric snapshots (last 60 points for charts)
  metricHistory: [],

  metrics: {
    cpu: 62,
    ram: 78,
    disk: 41,
    network: 55,
    dbQueries: 33,
    threats: 8,
    activeUsers: 1247,
    uptime: 99.97,
    requestsToday: 48291,
    threatsBlocked: 3,
    responseTimeMs: 142,
    errorRate: 0.4,
    serverStartedAt: new Date().toISOString(),
  },
};

// Seed logs
[
  { level: "CRITICAL", source: "api/v2/auth",   message: "SQL injection pattern detected & blocked" },
  { level: "WARNING",  source: "worker.js:142", message: "Memory usage exceeded 80% threshold" },
  { level: "FIXED",    source: "DB connection", message: "Pool timeout resolved by AI agent" },
  { level: "ERROR",    source: "POST /upload",  message: "Malformed payload, 413 returned" },
  { level: "INFO",     source: "SSL cert",      message: "Auto-renewed, valid 90 days" },
  { level: "OK",       source: "healthcheck",   message: "All 4 servers responding normally" },
].forEach((l, i) =>
  db.logs.push({ id: uuidv4(), ...l, time: new Date(Date.now() - (i + 1) * 7 * 60000).toISOString() })
);

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════
function makeTokens(user) {
  const access = jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
  const refresh = jwt.sign(
    { id: user.id },
    JWT_REFRESH,
    { expiresIn: "30d" }
  );
  const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
  db.refreshTokens[refresh] = { userId: user.id, expiresAt };
  return { access, refresh };
}

function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, avatar: u.avatar, createdAt: u.createdAt, lastSeen: u.lastSeen };
}

function addLog(level, source, message) {
  const log = { id: uuidv4(), level, source, message, time: new Date().toISOString() };
  db.logs.unshift(log);
  if (db.logs.length > 1000) db.logs.length = 1000;
  broadcast({ type: "new_log", data: log });
  return log;
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════
function auth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    // update lastSeen
    const u = db.users.find(u => u.id === req.user.id);
    if (u) u.lastSeen = new Date().toISOString();
    next();
  } catch (e) {
    if (e.name === "TokenExpiredError")
      return res.status(401).json({ error: "Token expired", code: "TOKEN_EXPIRED" });
    res.status(401).json({ error: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin")
    return res.status(403).json({ error: "Admins only" });
  next();
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — HEALTH
// ════════════════════════════════════════════════════════════════════════════
app.get("/", (req, res) => res.json({
  status: "ok",
  service: "Dex-X API",
  version: "2.0.0",
  environment: NODE_ENV,
  uptime: Math.floor(process.uptime()) + "s",
}));

app.get("/health", (req, res) => res.json({
  status: "healthy",
  db: "in-memory",
  ws: wss?.clients?.size ?? 0,
  memory: process.memoryUsage(),
  uptime: process.uptime(),
}));

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — AUTH
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "name, email and password are required" });
  if (!/\S+@\S+\.\S+/.test(email))
    return res.status(400).json({ error: "Invalid email format" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  if (db.users.find(u => u.email === email.toLowerCase()))
    return res.status(409).json({ error: "Email already registered" });

  const user = {
    id: uuidv4(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    password: await bcrypt.hash(password, 12),
    role: "user",
    avatar: null,
    createdAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };
  db.users.push(user);
  addLog("INFO", "auth/register", `New user registered: ${user.email}`);

  const { access, refresh } = makeTokens(user);
  res.status(201).json({ token: access, refreshToken: refresh, user: safeUser(user) });
});

// POST /api/auth/login
app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid email or password" });

  user.lastSeen = new Date().toISOString();
  addLog("INFO", "auth/login", `Login: ${user.email} (${user.role})`);

  const { access, refresh } = makeTokens(user);
  res.json({ token: access, refreshToken: refresh, user: safeUser(user) });
});

// POST /api/auth/refresh  — get new access token
app.post("/api/auth/refresh", (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });

  const record = db.refreshTokens[refreshToken];
  if (!record) return res.status(401).json({ error: "Invalid refresh token" });
  if (new Date(record.expiresAt) < new Date()) {
    delete db.refreshTokens[refreshToken];
    return res.status(401).json({ error: "Refresh token expired" });
  }

  try {
    jwt.verify(refreshToken, JWT_REFRESH);
  } catch {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const user = db.users.find(u => u.id === record.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  delete db.refreshTokens[refreshToken];
  const { access, refresh: newRefresh } = makeTokens(user);
  res.json({ token: access, refreshToken: newRefresh });
});

// POST /api/auth/logout
app.post("/api/auth/logout", auth, (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) delete db.refreshTokens[refreshToken];
  addLog("INFO", "auth/logout", `Logout: ${req.user.email}`);
  res.json({ message: "Logged out" });
});

// GET /api/auth/me
app.get("/api/auth/me", auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(safeUser(user));
});

// PATCH /api/auth/me  — update profile
app.patch("/api/auth/me", auth, async (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const { name, avatar } = req.body || {};
  if (name?.trim()) user.name = name.trim();
  if (avatar !== undefined) user.avatar = avatar;

  addLog("INFO", "auth/profile", `Profile updated: ${user.email}`);
  res.json(safeUser(user));
});

// POST /api/auth/change-password
app.post("/api/auth/change-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword)
    return res.status(400).json({ error: "oldPassword and newPassword required" });
  if (newPassword.length < 6)
    return res.status(400).json({ error: "New password must be at least 6 characters" });

  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  if (!(await bcrypt.compare(oldPassword, user.password)))
    return res.status(401).json({ error: "Old password is incorrect" });

  user.password = await bcrypt.hash(newPassword, 12);
  addLog("INFO", "auth/password", `Password changed: ${user.email}`);
  res.json({ message: "Password updated successfully" });
});

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — METRICS
// ════════════════════════════════════════════════════════════════════════════

app.get("/api/metrics", auth, (req, res) => {
  res.json({
    ...db.metrics,
    connectedClients: wss?.clients?.size ?? 0,
    serverUptimeSeconds: Math.floor(process.uptime()),
  });
});

// GET /api/metrics/history — last N chart snapshots
app.get("/api/metrics/history", auth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 30, 60);
  res.json(db.metricHistory.slice(-limit));
});

// GET /api/metrics/summary — aggregated KPIs
app.get("/api/metrics/summary", auth, (req, res) => {
  const m = db.metrics;
  res.json({
    health: m.cpu < 80 && m.ram < 85 ? "healthy" : m.cpu < 90 ? "warning" : "critical",
    avgCpu:     m.cpu,
    avgRam:     m.ram,
    uptime:     m.uptime,
    activeUsers: m.activeUsers,
    threatsBlocked: m.threatsBlocked,
    requestsToday:  m.requestsToday,
    openAlerts: db.alerts.filter(a => !a.resolved).length,
  });
});

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — LOGS
// ════════════════════════════════════════════════════════════════════════════

app.get("/api/logs", auth, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 20, 200);
  const offset = parseInt(req.query.offset) || 0;
  const level  = req.query.level?.toUpperCase();

  let logs = level ? db.logs.filter(l => l.level === level) : db.logs;
  res.json({
    total: logs.length,
    data:  logs.slice(offset, offset + limit),
  });
});

app.post("/api/logs", auth, (req, res) => {
  const { level, source, message } = req.body || {};
  if (!level || !source || !message)
    return res.status(400).json({ error: "level, source, message required" });
  const allowed = ["INFO","WARNING","ERROR","CRITICAL","FIXED","OK"];
  if (!allowed.includes(level.toUpperCase()))
    return res.status(400).json({ error: `level must be one of: ${allowed.join(", ")}` });

  const log = addLog(level.toUpperCase(), source, message);
  res.status(201).json(log);
});

app.delete("/api/logs", auth, adminOnly, (req, res) => {
  const count = db.logs.length;
  db.logs.length = 0;
  addLog("INFO", "admin", `Logs cleared by ${req.user.email} (${count} entries removed)`);
  res.json({ message: `Cleared ${count} log entries` });
});

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — ALERTS
// ════════════════════════════════════════════════════════════════════════════

app.get("/api/alerts", auth, (req, res) => {
  const resolved = req.query.resolved;
  let alerts = db.alerts;
  if (resolved === "true")  alerts = alerts.filter(a => a.resolved);
  if (resolved === "false") alerts = alerts.filter(a => !a.resolved);
  res.json({ total: alerts.length, data: alerts });
});

app.post("/api/alerts", auth, (req, res) => {
  const { level, title, message } = req.body || {};
  if (!level || !title || !message)
    return res.status(400).json({ error: "level, title, message required" });

  const alert = {
    id: uuidv4(),
    level: level.toUpperCase(),
    title,
    message,
    resolved: false,
    createdAt: new Date().toISOString(),
    createdBy: req.user.email,
  };
  db.alerts.unshift(alert);
  addLog(alert.level, "alerts/create", `New alert: ${title}`);
  broadcast({ type: "new_alert", data: alert });
  res.status(201).json(alert);
});

app.patch("/api/alerts/:id/resolve", auth, (req, res) => {
  const alert = db.alerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: "Alert not found" });
  alert.resolved    = true;
  alert.resolvedAt  = new Date().toISOString();
  alert.resolvedBy  = req.user.email;
  addLog("OK", "alerts/resolve", `Alert resolved: ${alert.title} by ${req.user.email}`);
  broadcast({ type: "alert_resolved", data: alert });
  res.json(alert);
});

app.delete("/api/alerts/:id", auth, adminOnly, (req, res) => {
  const idx = db.alerts.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Alert not found" });
  db.alerts.splice(idx, 1);
  res.json({ message: "Alert deleted" });
});

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — USERS (admin)
// ════════════════════════════════════════════════════════════════════════════

app.get("/api/users", auth, adminOnly, (req, res) => {
  res.json(db.users.map(safeUser));
});

app.get("/api/users/:id", auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(safeUser(user));
});

app.patch("/api/users/:id/role", auth, adminOnly, (req, res) => {
  if (req.params.id === "user-001")
    return res.status(403).json({ error: "Cannot change root admin role" });
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  const { role } = req.body || {};
  if (!["admin","user"].includes(role))
    return res.status(400).json({ error: "role must be admin or user" });
  user.role = role;
  addLog("INFO", "admin/users", `Role of ${user.email} changed to ${role} by ${req.user.email}`);
  res.json(safeUser(user));
});

app.delete("/api/users/:id", auth, adminOnly, (req, res) => {
  if (req.params.id === "user-001")
    return res.status(403).json({ error: "Cannot delete root admin" });
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: "Cannot delete yourself" });
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  const [deleted] = db.users.splice(idx, 1);
  addLog("WARNING", "admin/users", `User deleted: ${deleted.email} by ${req.user.email}`);
  res.json({ message: "User deleted" });
});

// ════════════════════════════════════════════════════════════════════════════
// ROUTES — 404 fallback
// ════════════════════════════════════════════════════════════════════════════
app.use((req, res) => res.status(404).json({ error: `Route ${req.method} ${req.path} not found` }));

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// ════════════════════════════════════════════════════════════════════════════
// WEBSOCKET
// ════════════════════════════════════════════════════════════════════════════
const wss = new WebSocketServer({ server });
const clients = new Set();

function broadcast(data) {
  const msg = JSON.stringify(data);
  clients.forEach(ws => { try { if (ws.readyState === 1) ws.send(msg); } catch {} });
}

wss.on("connection", (ws, req) => {
  const url   = new URL(req.url, "http://localhost");
  const token = url.searchParams.get("token");

  if (token) {
    try { jwt.verify(token, JWT_SECRET); }
    catch { ws.close(4001, "Unauthorized"); return; }
  }

  clients.add(ws);
  ws.send(JSON.stringify({ type: "connected", message: "Dex-X Live Channel Ready", clients: clients.size }));

  // Ping-pong to detect dead connections
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "ping") ws.send(JSON.stringify({ type: "pong", ts: Date.now() }));
    } catch {}
  });

  ws.on("close", () => clients.delete(ws));
  ws.on("error", () => { clients.delete(ws); try { ws.terminate(); } catch {} });
});

// Kill dead connections every 30s
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) { clients.delete(ws); return ws.terminate(); }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on("close", () => clearInterval(pingInterval));

// ════════════════════════════════════════════════════════════════════════════
// REAL-TIME METRICS SIMULATOR
// ════════════════════════════════════════════════════════════════════════════
function drift(val, min, max, step = 3) {
  return +Math.max(min, Math.min(max, val + (Math.random() - 0.5) * step * 2)).toFixed(1);
}

setInterval(() => {
  const m = db.metrics;
  m.cpu            = drift(m.cpu, 15, 96, 4);
  m.ram            = drift(m.ram, 40, 94, 3);
  m.network        = drift(m.network, 5, 95, 6);
  m.responseTimeMs = Math.round(drift(m.responseTimeMs, 50, 800, 30));
  m.errorRate      = +drift(m.errorRate, 0, 5, 0.3).toFixed(2);
  m.activeUsers    = Math.round(drift(m.activeUsers, 600, 2500, 25));
  m.requestsToday += Math.floor(Math.random() * 8);

  // Save snapshot for history chart
  db.metricHistory.push({
    ts: Date.now(),
    cpu: m.cpu, ram: m.ram, network: m.network,
    responseTimeMs: m.responseTimeMs,
  });
  if (db.metricHistory.length > 60) db.metricHistory.shift();

  // Occasional threat
  if (Math.random() < 0.04) {
    m.threatsBlocked += 1;
    const ip  = `${rnd(1,254)}.${rnd(0,255)}.${rnd(0,255)}.${rnd(1,254)}`;
    const log = addLog("CRITICAL", "security/waf", `Threat blocked — IP ${ip} (${["SQLi","XSS","RCE","CSRF","DDoS"][Math.floor(Math.random()*5)]})`);

    // Auto-create alert for threats
    const alert = {
      id: uuidv4(), level: "CRITICAL",
      title: "Threat Detected",
      message: `Attack from ${ip} blocked automatically`,
      resolved: false,
      createdAt: new Date().toISOString(),
    };
    db.alerts.unshift(alert);
    broadcast({ type: "threat", data: { log, alert } });
  }

  broadcast({ type: "metrics_update", data: { ...m, connectedClients: clients.size } });
}, 2000);

function rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

// ════════════════════════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ════════════════════════════════════════════════════════════════════════════
function shutdown(sig) {
  console.log(`\n[${sig}] Graceful shutdown...`);
  server.close(() => {
    wss.close(() => {
      console.log("✅ Server closed cleanly.");
      process.exit(0);
    });
  });
  setTimeout(() => { console.error("Force exit."); process.exit(1); }, 8000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("uncaughtException",  e => { console.error("Uncaught:", e); });
process.on("unhandledRejection", e => { console.error("Unhandled:", e); });

// ════════════════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║          Dex-X Solution API v2.0             ║
╠══════════════════════════════════════════════╣
║  Port    : ${String(PORT).padEnd(34)}║
║  Env     : ${NODE_ENV.padEnd(34)}║
║  WS      : ws://localhost:${String(PORT).padEnd(18)}║
╠══════════════════════════════════════════════╣
║  Login   : admin@dex-x.io / admin123         ║
╚══════════════════════════════════════════════╝
`);
});

module.exports = { app, server };
