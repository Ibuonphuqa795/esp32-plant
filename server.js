// ============================================================
// SPORO - Dashboard giám sát cây giống tự động
// Backend: nhận dữ liệu ESP32, logic van tưới, nhật ký, đăng nhập,
// xuất CSV, thời tiết ngoài trời. Chạy local & Render.
// ============================================================

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ---- Parse cookie thủ công (không cần thư viện ngoài) ----
app.use((req, res, next) => {
  const header = req.headers.cookie || "";
  req.cookies = Object.fromEntries(
    header.split(";").map(c => c.trim().split("=").map(decodeURIComponent)).filter(a => a[0])
  );
  next();
});

// ============================================================
// TÀI KHOẢN + PHIÊN ĐĂNG NHẬP
// Dùng Postgres nếu có biến môi trường DATABASE_URL (bền vững),
// nếu không thì dùng bộ nhớ RAM (tạm, mất khi khởi động lại).
// ============================================================
const SEED = [
  { user: "khoa",  pass: "khoa123",   name: "Đăng Khoa" },
  { user: "phuc",  pass: "phuc123",   name: "Gia Phúc" },
  { user: "hung",  pass: "hung123",   name: "Thái Hưng" },
  { user: "quan",  pass: "quan123",   name: "Hoàng Quân" },
  { user: "tai",   pass: "tai123",    name: "Thành Tài" },
  { user: "admin", pass: "sporo2026", name: "Admin" }
];
const USE_DB = !!process.env.DATABASE_URL;
let pool = null;
let memUsers = []; // fallback: [{ user, name, hash }]

async function initAuth() {
  if (USE_DB) {
    const { Pool } = require("pg");
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id serial PRIMARY KEY,
      username text UNIQUE NOT NULL,
      name text NOT NULL,
      pass_hash text NOT NULL,
      created_at timestamptz DEFAULT now()
    )`);
    for (const s of SEED) {
      await pool.query(
        `INSERT INTO users(username,name,pass_hash) VALUES($1,$2,$3) ON CONFLICT (username) DO NOTHING`,
        [s.user, s.name, bcrypt.hashSync(s.pass, 10)]
      );
    }
    console.log("Auth: dùng Postgres (tài khoản lưu vĩnh viễn)");
  } else {
    memUsers = SEED.map(s => ({ user: s.user, name: s.name, hash: bcrypt.hashSync(s.pass, 10) }));
    console.log("Auth: dùng RAM (chưa có DATABASE_URL — tài khoản đăng ký sẽ mất khi khởi động lại)");
  }
}

async function findUser(username) {
  if (USE_DB) {
    const r = await pool.query("SELECT username,name,pass_hash FROM users WHERE username=$1", [username]);
    return r.rows[0] ? { user: r.rows[0].username, name: r.rows[0].name, hash: r.rows[0].pass_hash } : null;
  }
  return memUsers.find(u => u.user === username) || null;
}
async function createUser(username, name, pass) {
  const hash = bcrypt.hashSync(pass, 10);
  if (USE_DB) await pool.query("INSERT INTO users(username,name,pass_hash) VALUES($1,$2,$3)", [username, name, hash]);
  else memUsers.push({ user: username, name, hash });
}

const sessions = new Map(); // token -> { user, name }
function currentUser(req) {
  const tok = req.cookies["sporo_session"];
  return tok ? sessions.get(tok) : null;
}
function requireAuth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "unauthorized" });
  req.user = u;
  next();
}
function startSession(res, user, name) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { user, name });
  res.setHeader("Set-Cookie", `sporo_session=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);
}

app.post("/api/login", async (req, res) => {
  try {
    const user = String((req.body || {}).user || "").toLowerCase().trim();
    const pass = (req.body || {}).pass || "";
    const found = await findUser(user);
    if (!found || !bcrypt.compareSync(pass, found.hash)) {
      return res.status(401).json({ ok: false, error: "Sai tài khoản hoặc mật khẩu" });
    }
    startSession(res, found.user, found.name);
    res.json({ ok: true, name: found.name });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Lỗi máy chủ" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const user = String((req.body || {}).user || "").toLowerCase().trim();
    const name = String((req.body || {}).name || "").trim();
    const pass = (req.body || {}).pass || "";
    if (!/^[a-z0-9_]{3,20}$/.test(user)) return res.status(400).json({ ok: false, error: "Tài khoản 3–20 ký tự, chỉ chữ thường/số/gạch dưới" });
    if (!name) return res.status(400).json({ ok: false, error: "Vui lòng nhập tên hiển thị" });
    if (String(pass).length < 6) return res.status(400).json({ ok: false, error: "Mật khẩu tối thiểu 6 ký tự" });
    if (await findUser(user)) return res.status(409).json({ ok: false, error: "Tài khoản đã tồn tại" });
    await createUser(user, name, pass);
    startSession(res, user, name);
    res.json({ ok: true, name });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Lỗi máy chủ khi đăng ký" });
  }
});

app.post("/api/logout", (req, res) => {
  const tok = req.cookies["sporo_session"];
  if (tok) sessions.delete(tok);
  res.setHeader("Set-Cookie", `sporo_session=; HttpOnly; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "unauthorized" });
  res.json({ user: u.user, name: u.name });
});

// ---- Chặn truy cập dashboard khi chưa đăng nhập ----
app.get(["/", "/index.html"], (req, res) => {
  if (currentUser(req)) return res.sendFile(path.join(__dirname, "public", "index.html"));
  res.redirect("/login.html");
});

// Static: cho phép login.html + tài nguyên, KHÔNG tự động phục vụ index
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ============================================================
// CẤU HÌNH & TRẠNG THÁI
// ============================================================
let config = { moistureOn: 45, moistureOff: 65, tempMin: 25, tempMax: 30, waterDuration: 13 };

let latest = { temp: null, moisture: null, time: null };
const history = [];
const MAX_HISTORY = 500;
const events = [];
const MAX_EVENTS = 50;
let valveState = "OFF";
let inZoneCount = 0, totalCount = 0;

function addEvent(type, detail) {
  events.unshift({ time: new Date().toISOString(), type, detail });
  if (events.length > MAX_EVENTS) events.pop();
}

// ---- ESP32 gửi dữ liệu (KHÔNG cần đăng nhập) ----
app.get("/api/update", (req, res) => {
  const temp = parseFloat(req.query.temp);
  const moisture = parseFloat(req.query.moisture);
  if (Number.isNaN(temp) || Number.isNaN(moisture)) {
    return res.status(400).json({ ok: false, error: "Thiếu hoặc sai temp/moisture" });
  }
  latest = { temp, moisture, time: new Date().toISOString() };
  history.push(latest);
  if (history.length > MAX_HISTORY) history.shift();

  totalCount++;
  if (temp >= config.tempMin && temp <= config.tempMax) inZoneCount++;

  if (valveState === "OFF" && moisture < config.moistureOn) {
    valveState = "ON";
    addEvent("Tưới", `Ẩm ${moisture}% < ${config.moistureOn}% → tưới ${config.waterDuration}s`);
  } else if (valveState === "ON" && moisture >= config.moistureOff) {
    valveState = "OFF";
    addEvent("Tắt", `Ẩm đạt ${moisture}% ≥ ${config.moistureOff}% → tắt van`);
  }
  if (temp > config.tempMax + 5) addEvent("Cảnh báo", `Nhiệt độ cao ${temp}°C`);
  else if (temp < config.tempMin - 5) addEvent("Cảnh báo", `Nhiệt độ thấp ${temp}°C`);

  res.json({ ok: true, received: latest, valve: valveState });
});

// ---- Dashboard lấy dữ liệu (cần đăng nhập) ----
app.get("/api/data", requireAuth, (req, res) => {
  const today = new Date().toDateString();
  const wateringToday = events.filter(e => e.type === "Tưới" && new Date(e.time).toDateString() === today).length;
  const lastWatering = events.find(e => e.type === "Tưới");
  const favorablePercent = totalCount > 0 ? Math.round((inZoneCount / totalCount) * 100) : 0;

  // Thống kê hôm nay từ history
  const todayHist = history.filter(h => new Date(h.time).toDateString() === today);
  let daily = null;
  if (todayHist.length) {
    const temps = todayHist.map(h => h.temp), moists = todayHist.map(h => h.moisture);
    daily = {
      tempMin: Math.min(...temps), tempMax: Math.max(...temps),
      tempAvg: temps.reduce((a, b) => a + b, 0) / temps.length,
      moistAvg: moists.reduce((a, b) => a + b, 0) / moists.length,
      samples: todayHist.length
    };
  }

  res.json({
    latest, history, events, valveState, config,
    user: req.user.name,
    stats: { wateringToday, lastWateringTime: lastWatering ? lastWatering.time : null, favorablePercent },
    daily
  });
});

app.get("/api/config", requireAuth, (req, res) => res.json(config));
app.post("/api/config", requireAuth, (req, res) => {
  const { moistureOn, moistureOff, tempMin, tempMax, waterDuration } = req.body || {};
  if (moistureOn != null) config.moistureOn = Number(moistureOn);
  if (moistureOff != null) config.moistureOff = Number(moistureOff);
  if (tempMin != null) config.tempMin = Number(tempMin);
  if (tempMax != null) config.tempMax = Number(tempMax);
  if (waterDuration != null) config.waterDuration = Number(waterDuration);
  addEvent("Cấu hình", `Cập nhật ngưỡng: tưới<${config.moistureOn}% / tắt≥${config.moistureOff}%`);
  res.json({ ok: true, config });
});

// ---- Xuất CSV ----
app.get("/api/export.csv", requireAuth, (req, res) => {
  const rows = ["time,temp,moisture", ...history.map(h => `${h.time},${h.temp},${h.moisture}`)];
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="sporo-data-${Date.now()}.csv"`);
  res.send(rows.join("\n"));
});

// ---- Thời tiết ngoài trời (Open-Meteo, miễn phí, không cần key) ----
app.get("/api/weather", requireAuth, async (req, res) => {
  try {
    const lat = req.query.lat || 11.94;   // Đà Lạt, Lâm Đồng
    const lon = req.query.lon || 108.44;
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m,relative_humidity_2m,weather_code`;
    const r = await fetch(url);
    const j = await r.json();
    res.json({
      temp: j.current.temperature_2m,
      humidity: j.current.relative_humidity_2m,
      code: j.current.weather_code,
      place: req.query.place || "Đà Lạt"
    });
  } catch (e) {
    res.status(502).json({ error: "weather unavailable" });
  }
});

app.get("/health", (req, res) => res.send("OK"));

initAuth()
  .catch(e => console.error("Lỗi khởi tạo Auth:", e.message))
  .finally(() => {
    app.listen(PORT, () => console.log(`SPORO server chay tai http://localhost:${PORT}`));
  });
