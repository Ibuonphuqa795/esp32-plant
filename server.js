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
  { user: "admin", pass: "admin123",  name: "Admin" }
];
const USE_DB = !!process.env.DATABASE_URL;
let pool = null;
let memUsers = []; // fallback: [{ user, name, hash }]

// Chuẩn hoá tên đăng nhập để giảm lỗi khi người dùng gõ chữ hoa / dấu tiếng Việt / khoảng trắng.
// "Tài Nguyễn" -> "tai_nguyen", "MEOCHIT" -> "meochit". Đăng nhập cũng dùng hàm này nên gõ có dấu vẫn vào được.
function normUser(raw) {
  return String(raw || "")
    .normalize("NFD").replace(/[̀-ͯ]/g, "") // bỏ dấu thanh + dấu mũ
    .replace(/đ/g, "d").replace(/Đ/g, "d")  // đ / Đ -> d
    .toLowerCase().trim()
    .replace(/\s+/g, "_")            // khoảng trắng -> gạch dưới
    .replace(/[^a-z0-9_]/g, "");     // bỏ mọi ký tự còn lại không hợp lệ
}
// Truy vấn DB có thử lại 1 lần khi Neon/Render đóng kết nối nhàn rỗi (giảm lỗi 500)
async function q(sql, params) {
  try { return await pool.query(sql, params); }
  catch (e) {
    if (/terminat|connection|ECONNRESET|timeout|socket|ended/i.test(e.message || "")) {
      return await pool.query(sql, params); // thử lại 1 lần
    }
    throw e;
  }
}

async function initAuth() {
  if (USE_DB) {
    const { Pool } = require("pg");
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5, idleTimeoutMillis: 30000, connectionTimeoutMillis: 15000
    });
    pool.on("error", err => console.error("PG pool error:", err.message)); // không để lỗi kết nối làm sập server
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id serial PRIMARY KEY,
      username text UNIQUE NOT NULL,
      name text NOT NULL,
      pass_hash text NOT NULL,
      created_at timestamptz DEFAULT now()
    )`);
    for (const s of SEED) {
      await pool.query(
        `INSERT INTO users(username,name,pass_hash) VALUES($1,$2,$3)
         ON CONFLICT (username) DO UPDATE SET pass_hash = EXCLUDED.pass_hash, name = EXCLUDED.name`,
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
    const r = await q("SELECT username,name,pass_hash FROM users WHERE username=$1", [username]);
    return r.rows[0] ? { user: r.rows[0].username, name: r.rows[0].name, hash: r.rows[0].pass_hash } : null;
  }
  return memUsers.find(u => u.user === username) || null;
}
async function createUser(username, name, pass) {
  const hash = bcrypt.hashSync(pass, 10);
  if (USE_DB) await q("INSERT INTO users(username,name,pass_hash) VALUES($1,$2,$3)", [username, name, hash]);
  else memUsers.push({ user: username, name, hash });
}
async function updatePassword(username, newPass) {
  const hash = bcrypt.hashSync(newPass, 10);
  if (USE_DB) await q("UPDATE users SET pass_hash=$1 WHERE username=$2", [hash, username]);
  else { const u = memUsers.find(x => x.user === username); if (u) u.hash = hash; }
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
    const user = normUser((req.body || {}).user);
    const pass = (req.body || {}).pass || "";
    const found = await findUser(user);
    if (!found || !bcrypt.compareSync(pass, found.hash)) {
      return res.status(401).json({ ok: false, error: "Sai tài khoản hoặc mật khẩu" });
    }
    startSession(res, found.user, found.name);
    res.json({ ok: true, name: found.name });
  } catch (e) {
    console.error("Lỗi /api/login:", e.message); // hiện lý do thật trong Render Logs
    res.status(500).json({ ok: false, error: "Máy chủ bận, thử lại sau vài giây" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const user = normUser((req.body || {}).user); // tự bỏ dấu / chữ hoa / khoảng trắng
    const name = String((req.body || {}).name || "").trim();
    const pass = (req.body || {}).pass || "";
    if (user.length < 3 || user.length > 20) {
      return res.status(400).json({ ok: false, error: 'Tên đăng nhập (sau khi bỏ dấu) phải 3–20 ký tự chữ/số/gạch dưới. Gợi ý: dùng dạng không dấu như "tai_nguyen".' });
    }
    if (!name) return res.status(400).json({ ok: false, error: "Vui lòng nhập tên hiển thị" });
    if (String(pass).length < 6) return res.status(400).json({ ok: false, error: "Mật khẩu tối thiểu 6 ký tự" });
    if (await findUser(user)) return res.status(409).json({ ok: false, error: `Tài khoản "${user}" đã tồn tại, chọn tên khác` });
    await createUser(user, name, pass);
    startSession(res, user, name);
    res.json({ ok: true, name, user }); // trả về tên đăng nhập đã chuẩn hoá để client hiển thị
  } catch (e) {
    console.error("Lỗi /api/register:", e.message);
    res.status(500).json({ ok: false, error: "Máy chủ bận khi đăng ký, thử lại sau vài giây" });
  }
});

app.post("/api/change-password", requireAuth, async (req, res) => {
  try {
    const oldPass = (req.body || {}).oldPass || "";
    const newPass = (req.body || {}).newPass || "";
    const found = await findUser(req.user.user);
    if (!found || !bcrypt.compareSync(oldPass, found.hash)) {
      return res.status(400).json({ ok: false, error: "Mật khẩu hiện tại không đúng" });
    }
    if (String(newPass).length < 6) return res.status(400).json({ ok: false, error: "Mật khẩu mới tối thiểu 6 ký tự" });
    await updatePassword(req.user.user, newPass);
    res.json({ ok: true });
  } catch (e) {
    console.error("Lỗi /api/change-password:", e.message);
    res.status(500).json({ ok: false, error: "Máy chủ bận, thử lại sau vài giây" });
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
let config = {
  moistureOn: 45, moistureOff: 65, tempMin: 25, tempMax: 30, waterDuration: 13,
  rainDelay: false, rainProbThreshold: 70,     // hoãn tưới khi xác suất mưa ≥ ngưỡng
  schedule: [],                                 // lịch tưới theo giờ: ["06:00","17:00"]
  weatherLat: 11.94, weatherLon: 108.44, weatherPlace: "Đà Lạt"
};

let latest = { temp: null, moisture: null, time: null };
const history = [];
const MAX_HISTORY = 500;
const events = [];
const MAX_EVENTS = 50;
let valveState = "OFF";
let manualMode = null; // "ON" = giữ van mở thủ công (auto không được tắt); null = tự động
let inZoneCount = 0, totalCount = 0;

// Trạng thái cho các tính năng mới
let rainProbNow = null;          // xác suất mưa hiện tại (server tự lấy) → hoãn tưới
let rainSkipActive = false;      // đang hoãn tưới do mưa (tránh ghi log lặp)
let lastAlertAt = {};            // chống spam cảnh báo Telegram
let disconnectAlerted = false;   // đã báo mất kết nối ESP32 chưa
let lastSchedFire = "";          // tránh kích hoạt lịch 2 lần trong cùng 1 phút

function addEvent(type, detail, meta) {
  const ev = { time: new Date().toISOString(), type, detail, meta: meta || null };
  events.unshift(ev);
  if (events.length > MAX_EVENTS) events.pop();
  dbInsertEvent(ev);
}

// ============================================================
// LƯU TRỮ DỮ LIỆU (Postgres) — bền vững, không mất khi restart
// ============================================================
async function initData() {
  if (!USE_DB) {
    console.log("Data: dùng RAM (chưa có DATABASE_URL — lịch sử mất khi khởi động lại)");
    return;
  }
  await pool.query(`CREATE TABLE IF NOT EXISTS readings (
    id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(), temp real, moisture real)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_readings_ts ON readings(ts)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sensor_events (
    id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(), type text, detail text, meta jsonb)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS app_config (id int PRIMARY KEY DEFAULT 1, data jsonb)`);
  // Nạp lại cấu hình đã lưu
  try {
    const r = await pool.query("SELECT data FROM app_config WHERE id=1");
    if (r.rows[0] && r.rows[0].data) config = { ...config, ...r.rows[0].data };
  } catch (e) {}
  // Nạp lịch sử & sự kiện gần đây vào RAM
  try {
    const r = await pool.query("SELECT ts,temp,moisture FROM readings ORDER BY ts DESC LIMIT $1", [MAX_HISTORY]);
    r.rows.reverse().forEach(x => history.push({ time: new Date(x.ts).toISOString(), temp: x.temp, moisture: x.moisture }));
    if (history.length) latest = history[history.length - 1];
    const totalR = await pool.query("SELECT count(*)::int c, count(*) FILTER (WHERE temp BETWEEN $1 AND $2)::int z FROM readings", [config.tempMin, config.tempMax]);
    if (totalR.rows[0]) { totalCount = totalR.rows[0].c || 0; inZoneCount = totalR.rows[0].z || 0; }
  } catch (e) {}
  try {
    const r = await pool.query("SELECT ts,type,detail,meta FROM sensor_events ORDER BY ts DESC LIMIT $1", [MAX_EVENTS]);
    r.rows.forEach(x => events.push({ time: new Date(x.ts).toISOString(), type: x.type, detail: x.detail, meta: x.meta }));
  } catch (e) {}
  console.log("Data: dùng Postgres (lịch sử, sự kiện & cấu hình lưu vĩnh viễn)");
}
function dbInsertReading(temp, moisture, timeIso) {
  if (!USE_DB || !pool) return;
  pool.query("INSERT INTO readings(ts,temp,moisture) VALUES($1,$2,$3)", [timeIso, temp, moisture]).catch(() => {});
}
function dbInsertEvent(ev) {
  if (!USE_DB || !pool) return;
  pool.query("INSERT INTO sensor_events(ts,type,detail,meta) VALUES($1,$2,$3,$4)",
    [ev.time, ev.type, ev.detail, ev.meta ? JSON.stringify(ev.meta) : null]).catch(() => {});
}
function dbSaveConfig() {
  if (!USE_DB || !pool) return;
  pool.query(`INSERT INTO app_config(id,data) VALUES(1,$1)
    ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data`, [JSON.stringify(config)]).catch(() => {});
}

// ============================================================
// CẢNH BÁO TELEGRAM (miễn phí) — bật bằng biến môi trường
// TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID
// ============================================================
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN, TG_CHAT = process.env.TELEGRAM_CHAT_ID;
function sendTelegram(text) {
  if (!TG_TOKEN || !TG_CHAT) return;
  fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: TG_CHAT, text })
  }).catch(() => {});
}
const ALERT_COOLDOWN = 15 * 60 * 1000; // 15 phút mỗi loại cảnh báo
function fireAlert(key, text) {
  const now = Date.now();
  if (lastAlertAt[key] && now - lastAlertAt[key] < ALERT_COOLDOWN) return;
  lastAlertAt[key] = now;
  sendTelegram(text);
}
function checkAlerts(temp, moisture) {
  if (temp > config.tempMax + 5) fireAlert("hot", `SPORO ⚠️ Nhiệt độ cao ${temp}°C (vượt ${config.tempMax + 5}°C)`);
  else if (temp < config.tempMin - 5) fireAlert("cold", `SPORO ⚠️ Nhiệt độ thấp ${temp}°C`);
  else lastAlertAt.hot = lastAlertAt.cold = 0;
  if (moisture < config.moistureOn - 10) fireAlert("dry", `SPORO 💧 Đất quá khô ${moisture}% — kiểm tra hệ thống tưới`);
  else lastAlertAt.dry = 0;
}
// Watchdog: cảnh báo khi ESP32 ngừng gửi dữ liệu quá lâu
const DISCONNECT_MS = 10 * 60 * 1000;
function checkDisconnect() {
  if (!latest.time) return;
  const gap = Date.now() - new Date(latest.time).getTime();
  if (gap > DISCONNECT_MS && !disconnectAlerted) {
    disconnectAlerted = true;
    const mins = Math.round(gap / 60000);
    sendTelegram(`SPORO 🔌 Mất kết nối ESP32 — không nhận dữ liệu ${mins} phút.`);
    addEvent("Cảnh báo", `Mất kết nối ESP32 (${mins} phút)`, { kind: "offline", mins });
  }
}

// ============================================================
// HOÃN TƯỚI KHI SẮP MƯA — server tự lấy xác suất mưa định kỳ
// ============================================================
async function pollWeather() {
  try {
    const lat = config.weatherLat, lon = config.weatherLon;
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&hourly=precipitation_probability&forecast_days=1&timezone=auto`;
    const r = await fetch(url);
    const j = await r.json();
    if (j.hourly && Array.isArray(j.hourly.precipitation_probability)) {
      const times = j.hourly.time || [], a = j.hourly.precipitation_probability;
      const nowH = new Date().getHours();
      let idx = times.findIndex(tt => new Date(tt).getHours() === nowH);
      if (idx < 0) idx = 0;
      // lấy max của giờ hiện tại và 1-2 giờ tới
      rainProbNow = Math.max(a[idx] || 0, a[idx + 1] || 0, a[idx + 2] || 0);
    }
  } catch (e) {}
}

// ============================================================
// LỊCH TƯỚI THEO GIỜ — kiểm tra định kỳ, khớp HH:MM (giờ VN)
// ============================================================
function checkSchedule() {
  if (!config.schedule || !config.schedule.length) return;
  const now = new Date().toLocaleTimeString("en-GB", { timeZone: "Asia/Ho_Chi_Minh", hour: "2-digit", minute: "2-digit" });
  if (config.schedule.includes(now) && lastSchedFire !== now) {
    lastSchedFire = now;
    const raining = config.rainDelay && rainProbNow != null && rainProbNow >= config.rainProbThreshold;
    if (raining) {
      addEvent("Hoãn", `Bỏ lịch tưới ${now} — sắp mưa (${rainProbNow}%)`, { kind: "rain_skip_sched", time: now, prob: rainProbNow });
      return;
    }
    valveState = "ON"; manualMode = "ON";
    addEvent("Tưới", `Tưới theo lịch ${now} (${config.waterDuration}s)`, { kind: "sched_on", time: now, dur: config.waterDuration });
    setTimeout(() => {
      valveState = "OFF"; manualMode = null;
      addEvent("Tắt", `Kết thúc tưới theo lịch ${now}`, { kind: "sched_off", time: now });
    }, Math.max(3, config.waterDuration) * 1000);
  }
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
  dbInsertReading(temp, moisture, latest.time);
  disconnectAlerted = false; // vừa có dữ liệu → xoá cờ mất kết nối

  totalCount++;
  if (temp >= config.tempMin && temp <= config.tempMax) inZoneCount++;

  // Bỏ qua điều khiển tự động khi đang tưới THỦ CÔNG (giữ van mở tới khi bấm Dừng)
  if (manualMode !== "ON") {
    const raining = config.rainDelay && rainProbNow != null && rainProbNow >= config.rainProbThreshold;
    if (valveState === "OFF" && moisture < config.moistureOn) {
      if (raining) {
        // Hoãn tưới vì sắp mưa — chỉ ghi log 1 lần cho mỗi đợt khô
        if (!rainSkipActive) {
          rainSkipActive = true;
          addEvent("Hoãn", `Hoãn tưới — xác suất mưa ${rainProbNow}% ≥ ${config.rainProbThreshold}%`,
            { kind: "rain_skip", prob: rainProbNow, moisture });
        }
      } else {
        rainSkipActive = false;
        valveState = "ON";
        addEvent("Tưới", `Ẩm ${moisture}% < ${config.moistureOn}% → tưới ${config.waterDuration}s`,
          { kind: "water", moisture, on: config.moistureOn, dur: config.waterDuration });
      }
    } else if (valveState === "ON" && moisture >= config.moistureOff) {
      valveState = "OFF";
      addEvent("Tắt", `Ẩm đạt ${moisture}% ≥ ${config.moistureOff}% → tắt van`,
        { kind: "stop", moisture, off: config.moistureOff });
    } else if (moisture >= config.moistureOn) {
      rainSkipActive = false; // đất đủ ẩm → kết thúc đợt hoãn
    }
  }
  if (temp > config.tempMax + 5) addEvent("Cảnh báo", `Nhiệt độ cao ${temp}°C`, { kind: "hot", temp });
  else if (temp < config.tempMin - 5) addEvent("Cảnh báo", `Nhiệt độ thấp ${temp}°C`, { kind: "cold", temp });

  checkAlerts(temp, moisture); // gửi cảnh báo Telegram (nếu đã cấu hình)

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
    rainProbNow, rainSkipActive,
    stats: { wateringToday, lastWateringTime: lastWatering ? lastWatering.time : null, favorablePercent },
    daily
  });
});

// ---- Lịch sử nhiều ngày (từ DB, gộp theo giờ) cho biểu đồ dài hạn ----
app.get("/api/history", requireAuth, async (req, res) => {
  const days = Math.min(30, Math.max(1, parseInt(req.query.days) || 7));
  if (!USE_DB || !pool) {
    return res.json({ db: false, points: history.map(h => ({ t: h.time, temp: h.temp, moisture: h.moisture })) });
  }
  try {
    const r = await pool.query(
      `SELECT date_trunc('hour', ts) AS h, avg(temp) AS temp, avg(moisture) AS moisture
       FROM readings WHERE ts > now() - (($1)::text || ' days')::interval
       GROUP BY h ORDER BY h`, [String(days)]);
    res.json({ db: true, points: r.rows.map(x => ({ t: x.h, temp: Number(x.temp), moisture: Number(x.moisture) })) });
  } catch (e) {
    res.status(500).json({ error: "history error" });
  }
});

app.get("/api/config", requireAuth, (req, res) => res.json(config));
app.post("/api/config", requireAuth, (req, res) => {
  const b = req.body || {};
  ["moistureOn", "moistureOff", "tempMin", "tempMax", "waterDuration", "rainProbThreshold", "weatherLat", "weatherLon"]
    .forEach(k => { if (b[k] != null && b[k] !== "" && !Number.isNaN(Number(b[k]))) config[k] = Number(b[k]); });
  if (b.rainDelay != null) config.rainDelay = !!b.rainDelay;
  if (Array.isArray(b.schedule)) config.schedule = b.schedule.filter(s => /^\d{2}:\d{2}$/.test(s)).slice(0, 12);
  if (b.weatherPlace != null) config.weatherPlace = String(b.weatherPlace).slice(0, 80);
  // Chỉ ghi log khi thay đổi NGƯỠNG (tránh ồn khi chỉ đổi vị trí thời tiết)
  const changedThresh = ["moistureOn", "moistureOff", "tempMin", "tempMax", "waterDuration"].some(k => b[k] != null);
  if (changedThresh) {
    addEvent("Cấu hình", `Cập nhật ngưỡng: tưới<${config.moistureOn}% / tắt≥${config.moistureOff}%`,
      { kind: "config", on: config.moistureOn, off: config.moistureOff });
  }
  dbSaveConfig();
  if (b.weatherLat != null || b.weatherLon != null) pollWeather(); // cập nhật ngay xác suất mưa cho vị trí mới
  res.json({ ok: true, config });
});

// ---- Tưới THỦ CÔNG (bật/tắt van bất kỳ lúc nào, không qua ngưỡng) ----
// ESP32 đọc trạng thái van trả về ở /api/update để điều khiển van thật.
app.post("/api/valve", requireAuth, (req, res) => {
  const action = String((req.body || {}).action || "").toLowerCase();
  if (action === "on") {
    valveState = "ON";
    manualMode = "ON"; // giữ van mở tới khi bấm Dừng
    addEvent("Tưới", "Tưới thủ công (bật van)", { kind: "manual_on", by: req.user.name });
  } else if (action === "off") {
    valveState = "OFF";
    manualMode = null; // trả về chế độ tự động
    addEvent("Tắt", "Tắt van thủ công", { kind: "manual_off", by: req.user.name });
  } else {
    return res.status(400).json({ ok: false, error: "action phải là on/off" });
  }
  res.json({ ok: true, valve: valveState, manualMode });
});

// ---- Xuất CSV (thời gian theo giờ Việt Nam) ----
function toVNTime(iso) {
  // Định dạng "YYYY-MM-DD HH:mm:ss" theo múi giờ Asia/Ho_Chi_Minh (UTC+7)
  return new Date(iso).toLocaleString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
}
app.get("/api/export.csv", requireAuth, (req, res) => {
  // Ép cột thời gian thành TEXT bằng cú pháp ="..." để Excel/WPS hiển thị đầy đủ
  // (tránh lỗi cột hiện "#####" do bị tự nhận là số/serial ngày tháng và co hẹp).
  // Tách thêm cột ngày & giờ riêng cho dễ lọc/tính toán.
  const rows = ["thời gian (GMT+7),ngày,giờ,nhiệt độ (°C),độ ẩm (%)"];
  for (const h of history) {
    const full = toVNTime(h.time);            // "2026-07-09 15:19:34"
    const [d, tm] = full.split(" ");
    rows.push(`="${full}",="${d}",="${tm}",${h.temp},${h.moisture}`);
  }
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="sporo-data-${Date.now()}.csv"`);
  res.send("﻿" + rows.join("\r\n")); // BOM + CRLF để Excel/WPS đọc đúng tiếng Việt
});

// ---- Tìm địa điểm theo tên (Open-Meteo Geocoding, miễn phí, không cần key) ----
app.get("/api/geocode", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.json({ results: [] });
    const lang = req.query.lang === "en" ? "en" : "vi";
    let results = [];

    // Nguồn 1: Open-Meteo geocoding (nhanh, phủ thành phố lớn)
    try {
      const url = `https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(q)}&count=8&language=${lang}&format=json`;
      const r = await fetch(url);
      const j = await r.json();
      results = (j.results || []).map(x => ({
        name: x.name, admin1: x.admin1 || "", country: x.country || "",
        country_code: x.country_code || "", lat: x.latitude, lon: x.longitude
      }));
    } catch (e) { /* bỏ qua, dùng nguồn 2 */ }

    // Nguồn 2 (bổ sung/dự phòng): Nominatim OpenStreetMap — phủ tốt hơn cho
    // địa danh nhỏ ở Việt Nam (phường, thị trấn, tên có dấu…). Bắt buộc User-Agent.
    if (results.length < 4) {
      try {
        const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=jsonv2&limit=8&accept-language=${lang}&addressdetails=1`;
        const r = await fetch(url, { headers: { "User-Agent": "SPORO-greenhouse-dashboard/1.0" } });
        const arr = await r.json();
        const extra = (Array.isArray(arr) ? arr : []).map(x => {
          const a = x.address || {};
          const name = a.city || a.town || a.village || a.suburb || a.county || a.state
                     || x.name || (x.display_name || "").split(",")[0].trim();
          return {
            name, admin1: a.state || a.county || "", country: a.country || "",
            country_code: (a.country_code || "").toUpperCase(),
            lat: Number(x.lat), lon: Number(x.lon)
          };
        }).filter(e => e.name && !Number.isNaN(e.lat) && !Number.isNaN(e.lon));
        // gộp, loại trùng theo toạ độ gần nhau (~5km)
        for (const e of extra) {
          if (!results.some(r0 => Math.abs(r0.lat - e.lat) < 0.05 && Math.abs(r0.lon - e.lon) < 0.05)) {
            results.push(e);
          }
        }
      } catch (e) { /* bỏ qua */ }
    }

    // Ưu tiên kết quả ở Việt Nam lên đầu
    results.sort((a, b) => (b.country_code === "VN") - (a.country_code === "VN"));
    res.json({ results: results.slice(0, 8) });
  } catch (e) {
    res.status(502).json({ error: "geocode unavailable" });
  }
});

// ---- Tìm tên nơi từ toạ độ (reverse geocode — BigDataCloud, miễn phí, không key) ----
// Dùng cho nút "Vị trí của tôi" (lấy toạ độ từ Geolocation của trình duyệt).
app.get("/api/revgeo", requireAuth, async (req, res) => {
  try {
    const lat = req.query.lat, lon = req.query.lon;
    if (lat == null || lon == null) return res.status(400).json({ error: "missing lat/lon" });
    const lg = req.query.lang === "en" ? "en" : "vi";
    const url = `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=${lg}`;
    const r = await fetch(url);
    const j = await r.json();
    const name = j.city || j.locality || j.principalSubdivision || j.countryName || (lg === "en" ? "Current location" : "Vị trí hiện tại");
    res.json({ name, admin: j.principalSubdivision || "", country: j.countryName || "", lat: Number(lat), lon: Number(lon) });
  } catch (e) {
    res.status(502).json({ error: "revgeo unavailable" });
  }
});

// ---- Thời tiết ngoài trời (Open-Meteo, miễn phí, không cần key) ----
// Trả về TOÀN BỘ dữ liệu trạm quan trắc có sẵn: nhiệt độ, cảm giác, độ ẩm,
// mưa, xác suất mưa, mã thời tiết, gió (tốc độ/hướng/giật), max/min trong ngày.
app.get("/api/weather", requireAuth, async (req, res) => {
  try {
    const lat = req.query.lat || 11.94;   // mặc định: Đà Lạt, Lâm Đồng
    const lon = req.query.lon || 108.44;
    const current = [
      "temperature_2m", "relative_humidity_2m", "apparent_temperature",
      "is_day", "precipitation", "rain", "weather_code", "cloud_cover",
      "pressure_msl", "wind_speed_10m", "wind_direction_10m", "wind_gusts_10m"
    ].join(",");
    const hourly = "precipitation_probability";
    const daily = [
      "temperature_2m_max", "temperature_2m_min",
      "precipitation_probability_max", "precipitation_sum",
      "wind_speed_10m_max", "sunrise", "sunset", "uv_index_max"
    ].join(",");
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}` +
      `&current=${current}&hourly=${hourly}&daily=${daily}` +
      `&timezone=auto&wind_speed_unit=ms&forecast_days=1`;
    const r = await fetch(url);
    const j = await r.json();
    const c = j.current || {};

    // Xác suất mưa của giờ hiện tại (lấy từ mảng hourly gần nhất)
    let precipProb = null;
    if (j.hourly && Array.isArray(j.hourly.precipitation_probability)) {
      const times = j.hourly.time || [];
      const nowH = new Date().getHours();
      let idx = times.findIndex(t => new Date(t).getHours() === nowH);
      if (idx < 0) idx = 0;
      precipProb = j.hourly.precipitation_probability[idx];
    }
    const d = j.daily || {};

    res.json({
      place: req.query.place || "Đà Lạt",
      lat: Number(lat), lon: Number(lon),
      temp: c.temperature_2m,
      feels: c.apparent_temperature,
      humidity: c.relative_humidity_2m,
      precip: c.precipitation,
      rain: c.rain,
      precipProb,
      code: c.weather_code,
      isDay: c.is_day,
      cloud: c.cloud_cover,
      pressure: c.pressure_msl,
      windSpeed: c.wind_speed_10m,
      windDir: c.wind_direction_10m,
      windGust: c.wind_gusts_10m,
      tempMax: d.temperature_2m_max ? d.temperature_2m_max[0] : null,
      tempMin: d.temperature_2m_min ? d.temperature_2m_min[0] : null,
      precipProbMax: d.precipitation_probability_max ? d.precipitation_probability_max[0] : null,
      precipSum: d.precipitation_sum ? d.precipitation_sum[0] : null,
      windMax: d.wind_speed_10m_max ? d.wind_speed_10m_max[0] : null,
      uvMax: d.uv_index_max ? d.uv_index_max[0] : null,
      sunrise: d.sunrise ? d.sunrise[0] : null,
      sunset: d.sunset ? d.sunset[0] : null,
      units: {
        temp: (j.current_units || {}).temperature_2m || "°C",
        wind: (j.current_units || {}).wind_speed_10m || "m/s",
        humidity: "%"
      }
    });
  } catch (e) {
    res.status(502).json({ error: "weather unavailable" });
  }
});

app.get("/health", (req, res) => res.send("OK"));

initAuth()
  .then(() => initData())
  .catch(e => console.error("Lỗi khởi tạo:", e.message))
  .finally(() => {
    // Tác vụ nền
    pollWeather();                              // lấy xác suất mưa ngay
    setInterval(pollWeather, 10 * 60 * 1000);   // và mỗi 10 phút
    setInterval(checkSchedule, 30 * 1000);      // kiểm tra lịch tưới mỗi 30s
    setInterval(checkDisconnect, 60 * 1000);    // watchdog mất kết nối mỗi 60s
    app.listen(PORT, () => console.log(`SPORO server chay tai http://localhost:${PORT}`));
  });
