/**
 * Kafetzoglou Mainframe ESP32 DNS Sinkhole (AdBlocker)
 * * Description:
 * This  turns an ESP32 into a DNS Server. It intercepts DNS requests from
 * connected devices. If a domain matches a blocklist, it returns "NXDOMAIN" 
 * (Non-Existent Domain), effectively blocking ads and trackers. 
 * If safe, it forwards the request to an upstream DNS (e.g., 9.9.9.9).
 * * Features:
 * - Web Dashboard with real-time charts (served from PROGMEM)
 * - WiFiManager for easy WiFi setup (no hardcoded credentials)
 * - mDNS support (access via http://adblock.local)
 * - OLED Display status
 * - SPIFFS support for persistent blocklists
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <vector>
#include <Preferences.h>
#include <ESPmDNS.h>      // Allows accessing device via "adblock.local"
#include <WiFiManager.h>  // Managed Captive Portal for WiFi credentials



// Default Upstream DNS (Quad9), will be overwritten by Settings
IPAddress upstreamDNS(9, 9, 9, 9);
Preferences preferences; // Non-volatile storage for saving settings

// OLED Display Configuration (0.96" I2C)
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// DNS Server Settings
WiFiUDP udpIn;   // UDP Object to listen for incoming queries (Port 53)
WiFiUDP udpOut;  // UDP Object to talk to the internet (Upstream DNS)
const int DNS_PORT      = 53;
const int DNS_MAX_LEN   = 512;  // Standard DNS packet size limit
const int DNS_TIMEOUTMS = 2000; // Timeout for upstream response

// Web Server on Port 80
WebServer server(80);


// Using std::vector for dynamic arrays of strings
std::vector<String> whitelist; 
std::vector<String> blocklist; 
std::vector<String> keywords;  

// --- STATISTICS ---
uint32_t blockedTotal = 0;   // Lifetime blocks
uint32_t totalQueries = 0;   // Lifetime queries
uint16_t blockedWindow = 0;  // Blocks in the last 10 seconds

// Rolling Window Logic (for "Live Speed")
const unsigned long WINDOW_MS = 10000;
const int MAX_BLOCK_LOG = 512;
unsigned long blockTimes[MAX_BLOCK_LOG] = {0};

// Timers
unsigned long lastOledUpdate = 0;
const unsigned long OLED_UPDATE_MS = 500; // Update screen every 0.5s

String lastBlockedShort = "-"; // Stores the name of the last blocked domain


struct ClientStats {
  IPAddress ip;
  uint32_t total;
  uint32_t blocked;
  bool used;
};
const int MAX_CLIENTS = 8; // Limit tracking to 8 devices to save RAM
ClientStats clients[MAX_CLIENTS];

// Stored in PROGMEM to save RAM.
const char DASHBOARD_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ESP32 AdBlock Pro</title>

<style>
  body { font-family: 'Segoe UI', sans-serif; background:#121212; color:#e0e0e0; margin:0; padding:20px; }
  h1 { margin-top:0; color: #4ea3ff; }
  h2 { margin:0 0 10px 0; font-size:1.1rem; color:#ddd; }

  /* Card and Grid Layout */
  .card { background:#1e1e1e; border-radius:12px; padding:20px; margin-bottom:20px; box-shadow:0 4px 15px rgba(0,0,0,0.5); border: 1px solid #333; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap:15px; }
  .label { color:#888; font-size:0.75rem; text-transform:uppercase; letter-spacing:1px; margin-bottom: 5px; }
  .value { font-size:1.4rem; font-weight:bold; color: #fff; }
  .sub-value { font-size:0.9rem; color:#666; }

  /* System Status Bar */
  .sys-bar { display:flex; gap:15px; flex-wrap:wrap; background:#252525; padding:10px 15px; border-radius:8px; margin-bottom:20px; font-size:0.9rem; color:#aaa; border-left: 4px solid #4ea3ff; }
  .sys-item strong { color: #fff; }

  /* Tables and Links */
  table { width:100%; border-collapse:collapse; margin-top:10px; }
  th, td { padding:10px; text-align:left; border-bottom:1px solid #333; font-size:0.9rem; }
  th { background:#252525; color:#aaa; font-weight:600; }
  tr:hover { background:#2a2a2a; }
  a { color:#4ea3ff; text-decoration:none; transition:0.2s; }
  a:hover { color:#7bc0ff; text-decoration:underline; }

  /* Navigation Menu */
  .menu { display:flex; gap:15px; flex-wrap:wrap; margin-bottom:15px; }
  .menu a { background:#2a2a2a; padding:8px 12px; border-radius:5px; font-weight:600; }
  .menu a:hover { background:#333; }
  .status-pill { background:#28a745; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.7rem; vertical-align:middle; }

  /* Charts */
  .chart-row { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:20px; margin-top:10px; }
  .chart-container { background:#181818; border-radius:10px; padding:10px; border:1px solid #333; }
  canvas { width:100%; max-width:100%; background:#101010; border-radius:6px; }
</style>

<script>
// --- Custom Vanilla JS Charting (No external libraries required) ---

let labels = [];
let totalSeries = [];
let blockedSeries = [];
const MAX_POINTS = 60; // Keep 60 points of history

// Function to draw line charts on HTML5 Canvas
function drawLineChart(canvasId, data, lineColor) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h); // Clear canvas

  if (!data || data.length < 2) {
    ctx.fillStyle = "#666"; ctx.font = "10px sans-serif";
    ctx.fillText("Waiting for data...", 10, h / 2); return;
  }

  // Define drawing area with padding
  const padLeft = 32, padRight = 50, padTop = 12, padBottom = 22;
  const innerW = w - padLeft - padRight;
  const innerH = h - padTop - padBottom;

  // Calculate Min/Max for auto-scaling
  let minVal = data[0], maxVal = data[0];
  for (let v of data) {
    if (v < minVal) minVal = v;
    if (v > maxVal) maxVal = v;
  }
  if (maxVal === minVal) maxVal = minVal + 1;
  const lastVal = data[data.length - 1];

  // Draw Background & Grid
  ctx.fillStyle = "#050505"; ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "#222"; ctx.lineWidth = 1; ctx.beginPath();
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const gy = padTop + (innerH / gridLines) * i;
    ctx.moveTo(padLeft, gy); ctx.lineTo(padLeft + innerW, gy);
  }
  ctx.stroke();

  // Draw Axes
  ctx.strokeStyle = "#555"; ctx.lineWidth = 1.2; ctx.beginPath();
  ctx.moveTo(padLeft, padTop); ctx.lineTo(padLeft, padTop + innerH);
  ctx.moveTo(padLeft, padTop + innerH); ctx.lineTo(padLeft + innerW, padTop + innerH);
  ctx.stroke();

  // Draw Labels
  ctx.fillStyle = "#aaa"; ctx.font = "10px sans-serif";
  const midVal = (minVal + maxVal) / 2;
  ctx.fillText(maxVal.toFixed(0), 4, padTop + 8);
  ctx.fillText(midVal.toFixed(0), 4, padTop + innerH / 2 + 3);
  ctx.fillText(minVal.toFixed(0), 4, padTop + innerH);

  // Draw the Data Line
  ctx.strokeStyle = lineColor; ctx.lineWidth = 2; ctx.beginPath();
  const n = data.length;
  let lastX = padLeft, lastY = padTop + innerH;
  for (let i = 0; i < n; i++) {
    const x = padLeft + (i / (n - 1)) * innerW;
    const t = (data[i] - minVal) / (maxVal - minVal);
    const y = padTop + innerH - t * innerH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    lastX = x; lastY = y;
  }
  ctx.stroke();

  // Draw current value badge
  ctx.fillStyle = lineColor; ctx.beginPath(); ctx.arc(lastX, lastY, 3, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = "rgba(0,0,0,0.7)";
  const bx = w - 44 - 4, by = padTop + 4;
  ctx.fillRect(bx, by, 44, 18); ctx.strokeStyle = "#444"; ctx.strokeRect(bx, by, 44, 18);
  ctx.fillStyle = "#ddd"; ctx.font = "11px sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.fillText(lastVal.toFixed(0), bx + 22, by + 9);
  ctx.textAlign = "left"; ctx.textBaseline = "alphabetic";
}

// Fetch JSON data from ESP32
async function loadStats() {
  try {
    const res = await fetch('/stats');
    const d = await res.json();

    // Update DOM elements
    document.getElementById('ip').textContent           = d.ip;
    document.getElementById('total').textContent        = d.totalQueries.toLocaleString();
    document.getElementById('blockedTotal').textContent = d.blockedTotal.toLocaleString();
    document.getElementById('blockedWindow').textContent= d.blockedWindow;
    document.getElementById('rules').textContent        = d.blocklistSize + " / " + d.keywordSize;
    document.getElementById('lastBlocked').textContent  = d.lastBlocked || '-';
    document.getElementById('ram').textContent    = d.freeHeap + " KB";
    document.getElementById('uptime').textContent = d.uptime;
    document.getElementById('rssi').textContent   = d.rssi + " dBm";

    // Update Client Table
    const tbody = document.getElementById('clients-body');
    tbody.innerHTML = '';
    d.clients.forEach(c => {
      const tr = document.createElement('tr');
      const pct = c.total > 0 ? ((c.blocked * 100.0) / c.total).toFixed(1) : '0.0';
      let color = "#e0e0e0";
      if (c.blocked > 100) color = "#ff6b6b";
      tr.innerHTML = '<td>' + c.ip + '</td><td>' + c.total + '</td><td style="color:' + color + '">' + c.blocked + '</td><td>' + pct + '%</td>';
      tbody.appendChild(tr);
    });

    // Update Chart Arrays
    const now = new Date();
    const label = now.toLocaleTimeString();
    labels.push(label);
    totalSeries.push(d.totalQueries);
    blockedSeries.push(d.blockedTotal);
    if (labels.length > MAX_POINTS) { labels.shift(); totalSeries.shift(); blockedSeries.shift(); }

    // Redraw
    drawLineChart('totalChart', totalSeries, '#4ea3ff');
    drawLineChart('blockedChart', blockedSeries, '#ff6b6b');

  } catch (e) { console.error(e); }
}

window.onload = function() {
  loadStats();
  setInterval(loadStats, 5000); // Poll every 5 seconds
};
</script>
</head>
<body>
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
    <h1>ESP32 AdBlock <span class="status-pill">PRO</span></h1>
  </div>

  <div class="sys-bar">
    <div class="sys-item">RAM: <strong id="ram">-</strong></div>
    <div class="sys-item">WiFi: <strong id="rssi">-</strong></div>
    <div class="sys-item">Uptime: <strong id="uptime">-</strong></div>
  </div>

  <div class="card">
    <div class="menu">
       <a href="/upload">📂 Lists</a>
       <a href="/whitelist">🛡️ Whitelist</a>
       <a href="/keywords" style="color:#ff8e8e">🔑 Keywords</a>
       <a href="/settings">⚙️ Settings</a>
       <a href="/reset_wifi" style="color:#f39c12">⚠️ Reset WiFi</a>
    </div>

    <div class="grid">
      <div><div class="label">Device IP</div><div class="value" id="ip">-</div></div>
      <div><div class="label">Total Queries</div><div class="value" id="total">0</div></div>
      <div><div class="label">Ads/Analytics Blocked</div><div class="value" id="blockedTotal" style="color:#ff6b6b">0</div></div>
      <div><div class="label">Live Speed</div><div class="value" id="blockedWindow">0</div><div class="sub-value">blocks/10s</div></div>
      <div><div class="label">Active Rules</div><div class="value" id="rules">0</div></div>
    </div>

    <div style="margin-top:15px; padding-top:10px; border-top:1px solid #333;">
      <div class="label">LAST BLOCKED DOMAIN</div>
      <div class="value" id="lastBlocked" style="color:#ff6b6b; font-family:monospace; font-size:1.1rem">-</div>
    </div>
  </div>

  <div class="card">
    <h2>Traffic overview</h2>
    <div class="chart-row">
      <div class="chart-container"><div class="label">Total queries</div><canvas id="totalChart" width="400" height="200"></canvas></div>
      <div class="chart-container"><div class="label">Blocked queries</div><canvas id="blockedChart" width="400" height="200"></canvas></div>
    </div>
  </div>

  <div class="card">
    <div class="label">CONNECTED DEVICES</div>
    <table>
      <thead><tr><th>IP Address</th><th>Queries</th><th>Blocked</th><th>%</th></tr></thead>
      <tbody id="clients-body"></tbody>
    </table>
  </div>
  
  <div style="text-align:center; color:#555; font-size:0.8rem;">
    Access via: <a href="http://adblock.local" style="color:#666">http://adblock.local</a>
  </div>
</body>
</html>
)rawliteral";


// Log a block event with timestamp for the rolling window
void registerBlock() {
  blockedTotal++;
  unsigned long now = millis();
  static int idx = 0;
  blockTimes[idx] = now;
  idx = (idx + 1) % MAX_BLOCK_LOG; // Circular buffer
}

// Calculate how many blocks happened in the last WINDOW_MS
void updateWindow() {
  unsigned long now = millis();
  uint16_t count = 0;
  for (int i = 0; i < MAX_BLOCK_LOG; i++) {
    if (blockTimes[i] != 0 && (now - blockTimes[i]) <= WINDOW_MS) count++;
  }
  blockedWindow = count;
}

// Draw status text on the OLED
void drawOled(String status, String info) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(F("ESP32 AdBlock"));
  
  display.setCursor(0, 15);
  display.println(status);
  
  display.setCursor(0, 30);
  display.println(info);
  
  // Bottom status bar
  display.setCursor(0, 50);
  display.print("B:"); display.print(blockedTotal);
  display.print(" Q:"); display.print(totalQueries);
  
  display.display();
}

// Find or Create a stats entry for a client IP
ClientStats* getClientStats(IPAddress ip) {
  // 1. Check if client already exists
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].used && clients[i].ip == ip) return &clients[i];
  }
  // 2. Find an empty slot
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (!clients[i].used) {
      clients[i].used = true;
      clients[i].ip = ip;
      clients[i].total = 0;
      clients[i].blocked = 0;
      return &clients[i];
    }
  }
  // 3. If full, overwrite the least active client
  int idxMin = 0;
  uint32_t minScore = clients[0].total;
  for (int i = 1; i < MAX_CLIENTS; i++) {
    if (clients[i].total < minScore) {
      minScore = clients[i].total;
      idxMin = i;
    }
  }
  clients[idxMin].used = true;
  clients[idxMin].ip = ip;
  clients[idxMin].total = 0;
  clients[idxMin].blocked = 0;
  return &clients[idxMin];
}

// Helper to parse DNS Question Name (e.g., converts 3www6google3com0 -> www.google.com)
String readQName(uint8_t* buf, int len, int& offset) {
  String qname;
  while (offset < len) {
    uint8_t labellen = buf[offset];
    if (labellen == 0) { offset++; break; } // End of name
    if (offset + 1 + labellen > len) break; // Buffer overflow safety
    if (qname.length() > 0) qname += '.';
    for (int i = 0; i < labellen; i++) {
      qname += (char)buf[offset + 1 + i];
    }
    offset += 1 + labellen;
  }
  return qname;
}

bool domainMatchesWhitelist(const String& qname) {
  String lower = qname;
  lower.toLowerCase();
  for (const String& dom : whitelist) {
    if (lower == dom || lower.endsWith("." + dom)) return true;
  }
  return false;
}

bool domainMatchesKeywords(const String& qname) {
  String lower = qname;
  lower.toLowerCase();
  for (const String& key : keywords) {
    if (key.length() > 0 && lower.indexOf(key) != -1) return true;
  }
  return false;
}

bool domainMatchesBlocklist(const String& qname) {
  String lower = qname;
  lower.toLowerCase();
  for (const String& dom : blocklist) {
    if (dom.length() == 0) continue;
    if (lower == dom) return true;
    if (lower.endsWith("." + dom)) return true; // Block subdomains too
  }
  return false;
}

// MODIFY the buffer to return "NXDOMAIN" (Sinkhole )
// This tells the requesting device: "This domain does not exist."
void makeNXDomain(uint8_t* buf, int len) {
  if (len < 12) return;
  
  // DNS Header Flags (Bytes 2 and 3)
  // QR (1 bit) : 1 (Response)
  // Opcode (4) : 0 (Standard)
  // AA (1)     : 1 (Authoritative)
  // TC (1)     : 0 (Truncated)
  // RD (1)     : 1 (Recursion Desired - copied from query)
  // RA (1)     : 1 (Recursion Available)
  // Z (3)      : 0
  // RCODE (4)  : 3 (NXDOMAIN) -> This is the key!

  uint8_t rd = buf[2] & 0x01; // Preserve RD bit from query
  buf[2] = 0x84 | rd;         // Set QR + AA + RD
  buf[3] = 0x83;              // RA + RCODE=3 (NXDOMAIN)

  // Clear counters for Answer, Authority, Additional records
  buf[4] = 0x00; buf[5] = 0x01; // Questions: 1 (keep original question)
  buf[6] = 0x00; buf[7] = 0x00; // Answer RRs: 0
  buf[8] = 0x00; buf[9] = 0x00; // Authority RRs: 0
  buf[10] = 0x00; buf[11] = 0x00; // Additional RRs: 0
}

// Proxy: Receive query, send to Upstream (9.9.9.9), send answer back to client
bool forwardDns(uint8_t* queryBuf, int queryLen, IPAddress clientIP, uint16_t clientPort) {
  // 1. Send query to Google/Cloudflare/Quad9
  if (!udpOut.beginPacket(upstreamDNS, DNS_PORT)) {
    return false;
  }
  udpOut.write(queryBuf, queryLen);
  udpOut.endPacket();

  // 2. Wait for response
  unsigned long start = millis();
  uint8_t respBuf[DNS_MAX_LEN];
  while (millis() - start < DNS_TIMEOUTMS) {
    int packetSize = udpOut.parsePacket();
    if (packetSize) {
      if (packetSize > DNS_MAX_LEN) packetSize = DNS_MAX_LEN;
      int respLen = udpOut.read(respBuf, packetSize);
      
      // 3. Forward response back to local device
      udpIn.beginPacket(clientIP, clientPort);
      udpIn.write(respBuf, respLen);
      udpIn.endPacket();
      return true;
    }
  }
  return false;
}

void loadDefaultBlocklist() {
  blocklist.clear();
  blocklist.push_back("doubleclick.net");
  blocklist.push_back("googlesyndication.com");
  blocklist.push_back("google-analytics.com");
  blocklist.push_back("ads.yahoo.com");
  blocklist.push_back("adnxs.com");
}

// Loads blocklist.txt from flash memory
bool loadBlocklistFromSPIFFS() {
  if (!SPIFFS.exists("/blocklist.txt")) return false;
  File f = SPIFFS.open("/blocklist.txt", "r");
  if (!f) return false;
  
  blocklist.clear();
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    
    // Skip empty lines and comments
    if (line.length() == 0 || line.startsWith("#")) continue;
    
    // Clean up Hosts file formats (e.g., "0.0.0.0 ad.com")
    line.replace("0.0.0.0", "");
    line.replace("127.0.0.1", "");
    line.trim(); 
    
    if (line.length() > 3) { 
      line.toLowerCase();
      blocklist.push_back(line);
    }
  }
  f.close();
  return true;
}

void loadWhitelist() {
  whitelist.clear();
  if (SPIFFS.exists("/whitelist.txt")) {
    File f = SPIFFS.open("/whitelist.txt", "r");
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() > 0) {
        line.toLowerCase();
        whitelist.push_back(line);
      }
    }
    f.close();
  }
  // Safety defaults so you don't break Google
  if (whitelist.empty()) {
    whitelist.push_back("google.com");
    whitelist.push_back("gmail.com");
  }
}

void loadKeywords() {
  keywords.clear();
  if (SPIFFS.exists("/keywords.txt")) {
    File f = SPIFFS.open("/keywords.txt", "r");
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() > 0) {
        line.toLowerCase();
        keywords.push_back(line);
      }
    }
    f.close();
  }
  if (keywords.empty()) {
    keywords.push_back("telemetry");
    keywords.push_back("adsystem");
  }
}

//WEB SERVER SETUP 

void setupWebServer() {
  // Serve the Dashboard
  server.on("/", HTTP_GET, []() { server.send_P(200, "text/html", DASHBOARD_HTML); });
  
  // JSON API for the JS Charts to pull data
  server.on("/stats", HTTP_GET, []() {
    unsigned long sec = millis() / 1000;
    unsigned long min = sec / 60;
    unsigned long hr = min / 60;
    String uptime = String(hr) + "h " + String(min % 60) + "m";

    String json = "{";
    json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
    json += "\"totalQueries\":" + String(totalQueries) + ",";
    json += "\"blockedTotal\":" + String(blockedTotal) + ",";
    json += "\"blockedWindow\":" + String(blockedWindow) + ",";
    json += "\"blocklistSize\":" + String((unsigned int)blocklist.size()) + ",";
    json += "\"keywordSize\":" + String((unsigned int)keywords.size()) + ",";
    json += "\"lastBlocked\":\"" + lastBlockedShort + "\",";
    json += "\"freeHeap\":" + String(ESP.getFreeHeap() / 1024) + ","; // KB
    json += "\"rssi\":" + String(WiFi.RSSI()) + ","; // Signal Strength
    json += "\"uptime\":\"" + uptime + "\",";

    json += "\"clients\":[";
    bool first = true;
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (!clients[i].used) continue;
      if (!first) json += ",";
      first = false;
      json += "{";
      json += "\"ip\":\"" + clients[i].ip.toString() + "\",";
      json += "\"total\":" + String(clients[i].total) + ",";
      json += "\"blocked\":" + String(clients[i].blocked);
      json += "}";
    }
    json += "]}";
    server.send(200, "application/json", json);
  });
  
  // UPLOAD PAGE (For blocklist.txt)
  server.on("/upload", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><body><h2>Upload blocklist.txt</h2><form method='POST' action='/upload' enctype='multipart/form-data'><input type='file' name='data'><input type='submit' value='Upload'></form></body></html>";
    server.send(200, "text/html", html);
  });
  
  server.on("/upload", HTTP_POST, [](){ server.send(200, "text/plain", "Done. Restarting..."); delay(1000); ESP.restart(); },
    []() {
      HTTPUpload& upload = server.upload();
      static File f;
      if (upload.status == UPLOAD_FILE_START) {
        if (SPIFFS.exists("/blocklist.txt")) SPIFFS.remove("/blocklist.txt");
        f = SPIFFS.open("/blocklist.txt", "w");
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (f) f.write(upload.buf, upload.currentSize);
      } else if (upload.status == UPLOAD_FILE_END) {
        if (f) f.close();
      }
    }
  );

  // SETTINGS PAGE (Change DNS IP) 
  server.on("/settings", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><body><h1>Configuration</h1><form method='POST' action='/settings/save'><p>DNS IP:<input type='text' name='dns' value='" + upstreamDNS.toString() + "'></p><input type='submit' value='Save'></form></body></html>";
    server.send(200, "text/html", html);
  });
  server.on("/settings/save", HTTP_POST, []() {
    if (server.hasArg("dns")) {
      String newIP = server.arg("dns");
      IPAddress tempIP;
      if (tempIP.fromString(newIP)) {
        preferences.putString("dns_ip", newIP); 
        server.send(200, "text/plain", "Saved. Restarting...");
        delay(1000);
        ESP.restart();
      }
    }
  });

  //WHITELIST EDITOR
  server.on("/whitelist", HTTP_GET, []() {
    String currentWL = "";
    for(const auto& s : whitelist) currentWL += s + "\n";
    String html = "<!DOCTYPE html><html><body><h1>Whitelist</h1><form method='POST' action='/whitelist/save'><textarea name='list' style='width:100%;height:300px'>" + currentWL + "</textarea><br><input type='submit' value='Save'></form></body></html>";
    server.send(200, "text/html", html);
  });
  server.on("/whitelist/save", HTTP_POST, []() {
    if (server.hasArg("list")) {
      File f = SPIFFS.open("/whitelist.txt", "w");
      f.print(server.arg("list"));
      f.close();
      server.sendHeader("Location", "/whitelist");
      server.send(303);
      loadWhitelist(); // Reload into RAM
    }
  });

  // KEYWORDS EDITOR
  server.on("/keywords", HTTP_GET, []() {
    String currentKW = "";
    for(const auto& s : keywords) currentKW += s + "\n";
    String html = "<!DOCTYPE html><html><body><h1>Keywords</h1><form method='POST' action='/keywords/save'><textarea name='list' style='width:100%;height:300px'>" + currentKW + "</textarea><br><input type='submit' value='Save'></form></body></html>";
    server.send(200, "text/html", html);
  });
  server.on("/keywords/save", HTTP_POST, []() {
    if (server.hasArg("list")) {
      File f = SPIFFS.open("/keywords.txt", "w");
      f.print(server.arg("list"));
      f.close();
      server.sendHeader("Location", "/keywords");
      server.send(303);
      loadKeywords(); // Reload into RAM
    }
  });

  //  RESET WIFI SETTINGS 
  server.on("/reset_wifi", HTTP_GET, []() {
    server.send(200, "text/plain", "Clearing WiFi settings and restarting...");
    delay(1000);
    WiFiManager wm;
    wm.resetSettings(); // Wipes saved SSID/Pass
    ESP.restart();
  });

  server.begin();
}

//SETUP & LOOP 

void setup() {
  Serial.begin(115200);
  delay(1000);

  // 1. Load User Config
  preferences.begin("adblock_cfg", false);
  String savedDNS = preferences.getString("dns_ip", "1.1.1.1"); 
  if (upstreamDNS.fromString(savedDNS)) {
    Serial.println("DNS: " + savedDNS);
  } else {
    upstreamDNS = IPAddress(1,1,1,1);
  }

  // 2. Initialize OLED
  Wire.begin();
  if (display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    drawOled("Booting...", "Initializing...");
  }

  // 3. Initialize File System
  if (!SPIFFS.begin(true)) Serial.println("SPIFFS fail");
  
  if (!loadBlocklistFromSPIFFS()) loadDefaultBlocklist();
  loadWhitelist(); 
  loadKeywords();

  // 4. Connect to WiFi using WiFiManager (Captive Portal)
  drawOled("WiFi...", "Connecting...");
  WiFiManager wm;
  
  // If connection fails, create Access Point at 192.168.4.1
  wm.setAPStaticIPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  
  // Try to connect. If fail, start AP named "ESP32-AdBlock" with pass "12345678"
  bool res = wm.autoConnect("ESP32-AdBlock", "12345678");

  if(!res) {
    Serial.println("Failed to connect");
    drawOled("WiFi Fail", "Restarting...");
    delay(3000);
    ESP.restart();
  } 
  
  Serial.println("WiFi Connected");
  drawOled("WiFi OK", WiFi.localIP().toString());

  // 5. Start mDNS (allows access via http://adblock.local)
  if (MDNS.begin("adblock")) {
    Serial.println("mDNS responder started: http://adblock.local");
  }

  // 6. Start UDP Listener and Web Server
  if (udpIn.begin(DNS_PORT)) Serial.println("DNS Listening");
  udpOut.begin(0); // Random port for outgoing requests
  setupWebServer();
}

void loop() {
  // Handle HTTP requests (Dashboard)
  server.handleClient(); 

  // Handle UDP DNS Packets
  int len = udpIn.parsePacket();
  if (len) {
    IPAddress clientIP = udpIn.remoteIP();
    uint16_t clientPort = udpIn.remotePort();
    
    // Clear buffer if packet is massive (unlikely for standard DNS)
    if (len > DNS_MAX_LEN) {
      while (udpIn.available()) udpIn.read();
    } else {
      uint8_t dnsBuf[DNS_MAX_LEN];
      int readLen = udpIn.read(dnsBuf, len);
      
      // Basic DNS Header check
      if (readLen >= 12) {
        uint16_t qdCount = (dnsBuf[4] << 8) | dnsBuf[5]; // Question Count
        int offset = 12; // Skip Header
        String qname = readQName(dnsBuf, readLen, offset);
        
        // 1. Is it a query? (Check QR bit)
        bool isQuery = !(dnsBuf[2] & 0x80);
        ClientStats* cs = getClientStats(clientIP);
        
        if (isQuery && qdCount > 0) {
           totalQueries++;
           if (cs) cs->total++;
           
           // Priority 1: Check Whitelist (Always Allow)
           if (domainMatchesWhitelist(qname)) {
             forwardDns(dnsBuf, readLen, clientIP, clientPort);
           }
           // Priority 2: Check Keywords (Block if match)
           else if (domainMatchesKeywords(qname)) {
             registerBlock();
             if (cs) cs->blocked++;
             lastBlockedShort = "K:" + qname;
             makeNXDomain(dnsBuf, readLen); // Modify buffer to say "Not Found"
             
            
             udpIn.beginPacket(clientIP, clientPort);
             udpIn.write(dnsBuf, readLen);
             udpIn.endPacket();
           }
           // Priority 3: Check Blocklist (Block if match)
           else if (domainMatchesBlocklist(qname)) {
             registerBlock();
             if (cs) cs->blocked++;
             lastBlockedShort = qname;
             makeNXDomain(dnsBuf, readLen);
             
             udpIn.beginPacket(clientIP, clientPort);
             udpIn.write(dnsBuf, readLen);
             udpIn.endPacket();
           }
           // Priority 4: No rules matched? Forward to Internet
           else {
             forwardDns(dnsBuf, readLen, clientIP, clientPort);
           }
        } else {
            //Just pass it through
           forwardDns(dnsBuf, readLen, clientIP, clientPort);
        }
      }
    }
  }

  // Handle OLED Screen Updates (Non-blocking)
  unsigned long now = millis();
  if (now - lastOledUpdate > OLED_UPDATE_MS) {
    updateWindow(); // Recalculate "Live Speed"
    
    // Flip between showing IP and URL
    static bool flip = false;
    flip = !flip;
    String status = WiFi.localIP().toString();
    String info = "http://adblock.local";
    
    drawOled(status, flip ? info : ("Blocked: " + String(blockedTotal)));
    lastOledUpdate = now;
  }
}