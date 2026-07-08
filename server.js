// ============================================================
// SPORO - Dashboard giám sát cây giống tự động
// Nhận dữ liệu từ ESP32, suy ra trạng thái van tưới, ghi nhật ký,
// và phục vụ web dashboard.
// Chạy cả local (http://localhost:3000) lẫn Render (process.env.PORT).
// ============================================================

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---- Cấu hình ngưỡng (chỉnh được từ dashboard) ----
let config = {
  moistureOn: 45,   // Ẩm < 45% => bật van tưới
  moistureOff: 65,  // Ẩm >= 65% => tắt van
  tempMin: 25,      // Vùng nhiệt thuận lợi: cận dưới
  tempMax: 30,      // Vùng nhiệt thuận lợi: cận trên
  waterDuration: 13 // Thời lượng mỗi lần tưới (giây)
};

// ---- Trạng thái hệ thống ----
let latest = { temp: null, moisture: null, time: null };
const history = [];       // [{temp, moisture, time}]
const MAX_HISTORY = 500;
const events = [];        // [{time, type, detail}] - nhật ký tưới/cảnh báo
const MAX_EVENTS = 50;
let valveState = "OFF";   // "ON" khi đang tưới

// Đếm thống kê
let inZoneCount = 0;      // số mẫu nhiệt nằm trong vùng tối ưu
let totalCount = 0;

function addEvent(type, detail) {
  events.unshift({ time: new Date().toISOString(), type, detail });
  if (events.length > MAX_EVENTS) events.pop();
}

// ---- API: ESP32 gửi dữ liệu vào đây ----
// Ví dụ: GET /api/update?temp=28.5&moisture=42
app.get("/api/update", (req, res) => {
  const temp = parseFloat(req.query.temp);
  const moisture = parseFloat(req.query.moisture);

  if (Number.isNaN(temp) || Number.isNaN(moisture)) {
    return res.status(400).json({ ok: false, error: "Thiếu hoặc sai temp/moisture" });
  }

  latest = { temp, moisture, time: new Date().toISOString() };
  history.push(latest);
  if (history.length > MAX_HISTORY) history.shift();

  // Thống kê vùng nhiệt tối ưu
  totalCount++;
  if (temp >= config.tempMin && temp <= config.tempMax) inZoneCount++;

  // Logic van tưới (hysteresis)
  if (valveState === "OFF" && moisture < config.moistureOn) {
    valveState = "ON";
    addEvent("Tưới", `Ẩm ${moisture}% < ${config.moistureOn}% → tưới ${config.waterDuration}s`);
  } else if (valveState === "ON" && moisture >= config.moistureOff) {
    valveState = "OFF";
    addEvent("Tắt", `Ẩm đạt ${moisture}% ≥ ${config.moistureOff}% → tắt van`);
  }

  // Cảnh báo nhiệt độ ngoài vùng
  if (temp > config.tempMax + 5) {
    addEvent("Cảnh báo", `Nhiệt độ cao ${temp}°C`);
  } else if (temp < config.tempMin - 5) {
    addEvent("Cảnh báo", `Nhiệt độ thấp ${temp}°C`);
  }

  console.log(`[${latest.time}] temp=${temp}C moisture=${moisture}% valve=${valveState}`);
  return res.json({ ok: true, received: latest, valve: valveState });
});

// ---- API: dashboard lấy toàn bộ trạng thái ----
app.get("/api/data", (req, res) => {
  // Số lần tưới hôm nay
  const today = new Date().toDateString();
  const wateringToday = events.filter(
    e => e.type === "Tưới" && new Date(e.time).toDateString() === today
  ).length;
  const lastWatering = events.find(e => e.type === "Tưới");

  const favorablePercent = totalCount > 0 ? Math.round((inZoneCount / totalCount) * 100) : 0;

  res.json({
    latest,
    history,
    events,
    valveState,
    config,
    stats: {
      wateringToday,
      lastWateringTime: lastWatering ? lastWatering.time : null,
      favorablePercent
    }
  });
});

// ---- API: xem / chỉnh cấu hình ngưỡng ----
app.get("/api/config", (req, res) => res.json(config));

app.post("/api/config", (req, res) => {
  const { moistureOn, moistureOff, tempMin, tempMax, waterDuration } = req.body || {};
  if (moistureOn != null) config.moistureOn = Number(moistureOn);
  if (moistureOff != null) config.moistureOff = Number(moistureOff);
  if (tempMin != null) config.tempMin = Number(tempMin);
  if (tempMax != null) config.tempMax = Number(tempMax);
  if (waterDuration != null) config.waterDuration = Number(waterDuration);
  addEvent("Cấu hình", `Cập nhật ngưỡng: tưới<${config.moistureOn}% / tắt≥${config.moistureOff}%`);
  res.json({ ok: true, config });
});

app.get("/health", (req, res) => res.send("OK"));

app.listen(PORT, () => {
  console.log(`SPORO server chay tai http://localhost:${PORT}`);
});
