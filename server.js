// ESP32 Cloud Dashboard - Express server
// Nhận dữ liệu từ ESP32 và hiển thị lên web dashboard.
// Chạy được cả local (http://localhost:3000) lẫn Render (dùng process.env.PORT).

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Bộ nhớ tạm (lưu trong RAM) ----
// latest: giá trị mới nhất. history: lưu tối đa 100 điểm gần nhất để vẽ biểu đồ.
let latest = { temp: null, moisture: null, time: null };
const history = [];
const MAX_HISTORY = 100;

// Phục vụ file tĩnh trong thư mục /public (chứa index.html)
app.use(express.static(path.join(__dirname, "public")));

// ---- API: ESP32 gọi vào đây ----
// Ví dụ: GET /api/update?temp=28.5&moisture=65
app.get("/api/update", (req, res) => {
  const temp = parseFloat(req.query.temp);
  const moisture = parseFloat(req.query.moisture);

  if (Number.isNaN(temp) || Number.isNaN(moisture)) {
    return res.status(400).json({ ok: false, error: "Thiếu hoặc sai temp/moisture" });
  }

  latest = { temp, moisture, time: new Date().toISOString() };
  history.push(latest);
  if (history.length > MAX_HISTORY) history.shift();

  console.log(`[${latest.time}] temp=${temp}C moisture=${moisture}%`);
  return res.json({ ok: true, received: latest });
});

// ---- API: trang web gọi để lấy dữ liệu hiện tại + lịch sử ----
app.get("/api/data", (req, res) => {
  res.json({ latest, history });
});

// Kiểm tra server sống
app.get("/health", (req, res) => res.send("OK"));

app.listen(PORT, () => {
  console.log(`Server chay tai http://localhost:${PORT}`);
});
