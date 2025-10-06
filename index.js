import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

// Если ваш сервер стоит за nginx / LB и вы доверяете его заголовкам:
// позволит express корректно отдавать req.ip и req.protocol из x-forwarded-*
app.set("trust proxy", true);

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  // Добавил X-Req-Id и прочие служебные заголовки в CORS (по необходимости)
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Req-Id, X-Request-Id, X-Correlation-Id, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host"
  );
  next();
});

const KEITARO_URL = "https://origin.skytalonsacademy.lol/skytalonsplaying";

function normalizeIp(ip) {
  if (!ip) return "";
  // убираем ::ffff: префикс у ipv4-в-IPv6, оставляем остальное как есть
  return String(ip).replace(/^::ffff:/, "").trim();
}

function detectClientIp(req) {
  // 1) если пришёл X-Forwarded-For — берем первый элемент цепочки
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = String(xff).split(",")[0].trim();
    if (first) return normalizeIp(first);
  }

  // 2) пробуем express'овый req.ip (работает корректно при trust proxy=true)
  if (req.ip) return normalizeIp(req.ip);

  // 3) fallback на сокет
  const remote = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "";
  return normalizeIp(remote);
}

function genReqId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

app.get("/", async (req, res) => {
  try {
    const clientIp = detectClientIp(req);

    // Входящая цепочка (если есть)
    const incomingXFF = req.headers["x-forwarded-for"] || "";
    const incomingParts = String(incomingXFF)
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

    // Формируем исходную цепочку так, чтобы клиентский IP был ПЕРВЫМ и без дубликатов
    const outgoingParts = [clientIp, ...incomingParts.filter((ip) => ip !== clientIp && ip !== "unknown")].filter(Boolean);
    const outgoingXFF = outgoingParts.join(", ");

    // Корреляционный id — предпочитаем заголовки от клиента, иначе генерируем
    const reqId =
      req.headers["x-req-id"] ||
      req.headers["x-request-id"] ||
      req.headers["x-correlation-id"] ||
      genReqId();

    const forwardedProto = req.headers["x-forwarded-proto"] || req.protocol || (req.secure ? "https" : "http");
    const forwardedHost = req.headers["x-forwarded-host"] || req.headers.host || "";

    const fetchHeaders = {
      // передаём важные заголовки
      "User-Agent": req.headers["user-agent"] || "",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
      Accept: req.headers["accept"] || "*/*",

      // обязательные проксируемые заголовки
      "X-Forwarded-For": outgoingXFF,
      "X-Real-IP": clientIp,
      "X-Forwarded-Proto": forwardedProto,
      "X-Forwarded-Host": forwardedHost,
      "X-Req-Id": reqId,
    };

    // опционально: логируем какие заголовки ушли (удали в проде)
    console.debug("Outgoing to Keitaro headers:", fetchHeaders);

    const response = await fetch(KEITARO_URL, {
      redirect: "follow",
      headers: fetchHeaders,
    });

    if (response.url !== KEITARO_URL) {
      return res.json({
        image_url: "",
        offer_url: response.url,
      });
    }

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
        // если ссылка относительная — превращаем в абсолютную
        if (imageUrl && !/^https?:\/\//i.test(imageUrl)) {
          try {
            const baseUrl = new URL(KEITARO_URL);
            // гарантируем правильный путь: /lander/<LANDER_NAME>/<imageUrl>
            imageUrl = `${baseUrl.origin}/lander/${LANDER_NAME}/${imageUrl.replace(/^\/+/, "")}`;
          } catch (e) {
            console.error("Failed to build absolute URL:", e);
          }
        }
      }
    }


    res.json({
      image_url: imageUrl || "",
      offer_url: "",
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ error: "Failed to fetch Keitaro URL" });
  }
});

app.listen(PORT, () => {
  console.log("API running on port", PORT);
});
