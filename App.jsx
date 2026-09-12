import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend
} from "recharts";

/* ═══════════════════════════════════════════════════════════════════════════
   ⚙️  SETUP PROMPT — WHAT YOU NEED TO PROVIDE
   ───────────────────────────────────────────────────────────────────────────
   Everything below is OPTIONAL. With zero keys the app runs in DEMO MODE
   (fully functional mock data). Add keys in the "Setup & Keys" tab (persisted
   to localStorage) or via Vercel → Project → Environment Variables:

   DATABASE (Supabase)                     REQUIRED for persistence
     NEXT_PUBLIC_SUPABASE_URL              https://xxxx.supabase.co
     NEXT_PUBLIC_SUPABASE_ANON_KEY         public anon key
     SUPABASE_SERVICE_ROLE_KEY             server-side only (never ship to client)
     SUPABASE_BUCKET                       "forensic-archive"  (Storage bucket)
     → Run the SQL in Setup → "Database Schema" to create all 16 tables + RLS.

   LLM / MULTI-AGENT (Text, URL, Metadata, Adversarial, Simplifier agents)
     OPENAI_API_KEY  |  OPENROUTER_API_KEY  |  GROQ_API_KEY
     OLLAMA_BASE_URL (http://localhost:11434) + OLLAMA_MODEL (qwen2.5:14b)
     EMBEDDING_MODEL (text-embedding-3-small / nomic-embed-text)

   THREAT INTELLIGENCE FEEDS
     VIRUSTOTAL_API_KEY   ABUSEIPDB_API_KEY   IPINFO_TOKEN
     URLSCAN_API_KEY      RECORDED_FUTURE_API_KEY   HIBP_API_KEY
     (OpenPhish + URLhaus are keyless public feeds)

   INGESTION
     IMAP_HOST  IMAP_PORT  IMAP_USER  IMAP_PASS   MTA_WEBHOOK_SECRET

   SUPPORTING STORES
     DATABASE_URL (Timescale/pgvector) · NEO4J_URI/USER/PASSWORD
     ELASTICSEARCH_URL · REDIS_URL · SENTRY_DSN

   NOTE: no animation library is imported — all motion is pure CSS keyframes,
   so there are no peer-dependency/binding errors in v0, Vercel or CRA.
   ═══════════════════════════════════════════════════════════════════════════ */

const readEnv = (k) => {
  try { if (typeof process !== "undefined" && process.env && process.env[k]) return process.env[k]; } catch (e) {}
  try { if (typeof window !== "undefined" && window.__APP_CONFIG__ && window.__APP_CONFIG__[k]) return window.__APP_CONFIG__[k]; } catch (e) {}
  return "";
};
const LS_KEY = "sentinelgrid.config.v1";
const loadLS = () => { try { return JSON.parse(localStorage.getItem(LS_KEY) || "{}"); } catch (e) { return {}; } };
const saveLS = (o) => { try { localStorage.setItem(LS_KEY, JSON.stringify(o)); } catch (e) {} };
const cfgGet = (k) => loadLS()[k] || readEnv(k) || "";
const cfgSet = (k, v) => { const o = loadLS(); o[k] = v; saveLS(o); };

/* ── deterministic pseudo-random ─────────────────────────────────────────── */
const hashStr = (s) => { let h = 2166136261; const str = s || ""; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return Math.abs(h); };
const rnd = (seed) => { const x = Math.sin(seed * 12.9898) * 43758.5453; return x - Math.floor(x); };
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const fmt = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "K" : String(n));
const pad = (n) => String(n).padStart(2, "0");
const ago = (ts) => {
  const s = Math.max(1, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};

/* ── geo projection (equirectangular, viewBox 1000x500) ──────────────────── */
const PX = (lon) => ((lon + 180) / 360) * 1000;
const PY = (lat) => ((90 - lat) / 180) * 500;
const proj = (lon, lat) => [PX(lon), PY(lat)];
const poly = (pts) => "M" + pts.map((p) => PX(p[0]).toFixed(1) + "," + PY(p[1]).toFixed(1)).join("L") + "Z";

const CONTINENTS = [
  [[-168,66],[-160,71],[-140,70],[-125,70],[-110,68],[-95,70],[-85,73],[-75,68],[-65,60],[-56,52],[-66,45],[-70,42],[-75,35],[-81,26],[-84,30],[-90,29],[-97,26],[-105,22],[-110,24],[-115,30],[-122,36],[-124,43],[-130,52],[-140,60],[-150,59],[-160,55],[-165,60]],
  [[-97,18],[-92,15],[-88,16],[-84,10],[-79,9],[-83,8],[-88,13],[-95,16],[-105,20],[-100,22]],
  [[-79,9],[-72,12],[-62,10],[-52,5],[-44,-2],[-37,-5],[-35,-9],[-39,-15],[-42,-23],[-48,-28],[-53,-34],[-58,-40],[-62,-45],[-66,-52],[-70,-55],[-73,-50],[-72,-42],[-71,-33],[-70,-23],[-75,-15],[-80,-6],[-81,0],[-79,4]],
  [[-17,15],[-17,21],[-10,26],[0,32],[10,37],[20,32],[30,31],[34,28],[38,22],[43,12],[51,12],[48,5],[41,-1],[40,-8],[35,-18],[32,-26],[27,-33],[20,-35],[17,-28],[12,-17],[9,-2],[4,4],[-4,5],[-8,10],[-13,12]],
  [[-10,37],[-9,43],[-2,43],[0,49],[-4,54],[-3,58],[5,58],[8,54],[12,54],[14,50],[19,45],[24,45],[28,46],[33,45],[40,48],[45,55],[40,60],[32,65],[25,70],[18,69],[12,64],[5,62],[-5,58]],
  [[30,50],[45,55],[58,52],[68,55],[76,58],[86,55],[100,52],[112,50],[122,54],[132,52],[140,52],[148,58],[160,62],[170,66],[180,68],[180,76],[160,72],[140,73],[120,75],[100,77],[80,74],[65,70],[55,68],[45,66],[36,60],[30,55]],
  [[70,26],[77,8],[80,12],[87,22],[92,21],[97,16],[100,10],[104,9],[108,11],[110,20],[117,24],[122,31],[121,25],[114,22],[108,15],[105,9],[100,6],[98,10],[94,16],[88,21],[80,15],[74,20]],
  [[113,-22],[114,-27],[117,-35],[124,-37],[132,-32],[138,-35],[145,-38],[150,-37],[153,-30],[150,-22],[145,-15],[142,-11],[136,-12],[130,-11],[125,-14],[118,-20]],
  [[-45,60],[-30,68],[-20,70],[-25,76],[-40,83],[-55,82],[-60,75],[-52,68],[-50,62]],
  [[95,-2],[105,-6],[115,-8],[125,-9],[133,-4],[128,0],[118,3],[108,4],[100,4]],
  [[165,-46],[172,-41],[178,-38],[176,-42],[170,-47],[166,-49]],
  [[43,-12],[50,-15],[50,-25],[45,-25],[43,-20]],
  [[129,32],[135,34],[141,40],[145,44],[141,45],[136,36],[131,31]],
  [[-8,54],[-6,57],[-3,58],[-2,54],[-5,50]]
];
const MAP_PATHS = CONTINENTS.map(poly);

const GEO_DB = {
  "185.220.101": { cc: "NL", country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.90, asn: "AS208294", org: "Tor Exit Relay / Zwiebelfreunde", type: "tor", tz: 2 },
  "54.212.19": { cc: "US", country: "United States", city: "Boardman, OR", lat: 45.83, lon: -119.70, asn: "AS16509", org: "Amazon AWS us-west-2", type: "hosting", tz: -7 },
  "103.224.182": { cc: "AU", country: "Australia", city: "Sydney", lat: -33.87, lon: 151.21, asn: "AS133612", org: "Trellian Pty Ltd", type: "hosting", tz: 10 },
  "45.155.205": { cc: "RU", country: "Russia", city: "Moscow", lat: 55.75, lon: 37.62, asn: "AS202425", org: "IP Volume Inc (bulletproof)", type: "vpn", tz: 3 },
  "196.196.53": { cc: "NG", country: "Nigeria", city: "Lagos", lat: 6.52, lon: 3.37, asn: "AS328543", org: "Layer-Host VPS", type: "hosting", tz: 1 },
  "203.119.8": { cc: "CN", country: "China", city: "Shenzhen", lat: 22.54, lon: 114.06, asn: "AS4134", org: "ChinaNet Guangdong", type: "residential", tz: 8 },
  "91.215.85": { cc: "UA", country: "Ukraine", city: "Kyiv", lat: 50.45, lon: 30.52, asn: "AS15626", org: "Cyberfort LLC", type: "vpn", tz: 3 },
  "172.67.188": { cc: "US", country: "United States", city: "San Francisco, CA", lat: 37.77, lon: -122.42, asn: "AS13335", org: "Cloudflare Inc", type: "cdn", tz: -7 },
  "104.47.58": { cc: "IE", country: "Ireland", city: "Dublin", lat: 53.35, lon: -6.26, asn: "AS8075", org: "Microsoft O365", type: "corporate", tz: 1 },
  "142.250.180": { cc: "US", country: "United States", city: "The Dalles, OR", lat: 45.60, lon: -121.17, asn: "AS15169", org: "Google LLC / Gmail", type: "corporate", tz: -7 },
  "157.240.8": { cc: "US", country: "United States", city: "Ashburn, VA", lat: 39.04, lon: -77.49, asn: "AS32934", org: "Meta Platforms", type: "corporate", tz: -4 }
};
const GEO_CITIES = [
  { cc: "BR", country: "Brazil", city: "São Paulo", lat: -23.55, lon: -46.63, tz: -3 },
  { cc: "IN", country: "India", city: "Mumbai", lat: 19.07, lon: 72.87, tz: 5.5 },
  { cc: "DE", country: "Germany", city: "Frankfurt", lat: 50.11, lon: 8.68, tz: 2 },
  { cc: "GB", country: "United Kingdom", city: "London", lat: 51.51, lon: -0.13, tz: 1 },
  { cc: "ID", country: "Indonesia", city: "Jakarta", lat: -6.21, lon: 106.85, tz: 7 },
  { cc: "VN", country: "Vietnam", city: "Hanoi", lat: 21.03, lon: 105.85, tz: 7 },
  { cc: "TR", country: "Türkiye", city: "Istanbul", lat: 41.01, lon: 28.98, tz: 3 },
  { cc: "ZA", country: "South Africa", city: "Johannesburg", lat: -26.20, lon: 28.05, tz: 2 },
  { cc: "RO", country: "Romania", city: "Bucharest", lat: 44.43, lon: 26.10, tz: 3 },
  { cc: "PK", country: "Pakistan", city: "Karachi", lat: 24.86, lon: 67.00, tz: 5 }
];
const geoFor = (ip) => {
  if (!ip) return null;
  const key = ip.split(".").slice(0, 3).join(".");
  if (GEO_DB[key]) return Object.assign({ ip: ip }, GEO_DB[key]);
  const h = hashStr(ip);
  const c = GEO_CITIES[h % GEO_CITIES.length];
  const types = ["vpn", "hosting", "residential", "residential"];
  return Object.assign({ ip: ip, asn: "AS" + (10000 + (h % 50000)), org: "Unknown / unclassified netblock", type: types[h % 4] }, c);
};
const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|255\.)/.test(ip || "");
const haversine = (a, b) => {
  const R = 6371;
  const dLa = ((b.lat - a.lat) * Math.PI) / 180;
  const dLo = ((b.lon - a.lon) * Math.PI) / 180;
  const s = Math.sin(dLa / 2) * Math.sin(dLa / 2) + Math.cos((a.lat * Math.PI) / 180) * Math.cos((b.lat * Math.PI) / 180) * Math.sin(dLo / 2) * Math.sin(dLo / 2);
  return Math.round(2 * R * Math.asin(Math.sqrt(s)));
};

/* ── email analysis engine ───────────────────────────────────────────────── */
const BRANDS = ["microsoft", "google", "apple", "amazon", "netflix", "dhl", "fedex", "paypal", "chase", "wellsfargo", "linkedin", "dropbox", "docusign", "maersk", "sap", "oracle", "coinbase"];
const URGENCY = [["urgent", 6], ["immediate action", 8], ["suspended", 7], ["verify your", 7], ["final notice", 8], ["account will be", 7], ["wire transfer", 9], ["gift card", 10], ["click here", 4], ["password expires", 8], ["unusual sign-in", 6], ["invoice attached", 5], ["payment overdue", 7], ["kindly", 3], ["dear customer", 4], ["dear user", 5], ["act now", 7], ["24 hours", 6], ["confirm your identity", 8], ["update your payment", 9], ["beneficiary", 5], ["swift code", 6]];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const d = [];
  for (let i = 0; i <= m; i++) { d[i] = [i]; for (let j = 1; j <= n; j++) d[i][j] = i === 0 ? j : 0; }
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return d[m][n];
}
const brandImpersonation = (host) => {
  const h = (host || "").toLowerCase().replace(/^www\./, "");
  const core = h.split(".")[0];
  for (let i = 0; i < BRANDS.length; i++) {
    const b = BRANDS[i];
    if (core === b) continue;
    if (core.indexOf(b) >= 0) return { brand: b, host: h, why: "Brand token '" + b + "' embedded in third-level label" };
    const dist = levenshtein(core.slice(0, 12), b.slice(0, 12));
    if (dist <= 2 && Math.abs(core.length - b.length) < 4) return { brand: b, host: h, why: "Edit-distance " + dist + " from '" + b + "' (homoglyph / typosquat)" };
  }
  return null;
};

function parseEmail(raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const sep = text.search(/\n\n/);
  const head = sep === -1 ? text : text.slice(0, sep);
  const body = sep === -1 ? "" : text.slice(sep + 2);
  const lines = [];
  head.split("\n").forEach((l) => {
    if (/^[ \t]/.test(l) && lines.length) lines[lines.length - 1] = lines[lines.length - 1] + " " + l.trim();
    else lines.push(l);
  });
  const headers = {};
  lines.forEach((l) => {
    const i = l.indexOf(":");
    if (i > 0) {
      const k = l.slice(0, i).trim().toLowerCase();
      const v = l.slice(i + 1).trim();
      if (!headers[k]) headers[k] = [];
      headers[k].push(v);
    }
  });
  const h = (k) => (headers[k] && headers[k][0]) || "";
  const received = (headers["received"] || []).map((v) => {
    const fromM = v.match(/from\s+([^\s(]+)/i);
    const parM = v.match(/\(([^)]*)\)/);
    const ipM = v.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
    const byM = v.match(/by\s+([^\s;]+)/i);
    const dateM = v.match(/;\s*(.+)$/);
    const parHost = parM ? parM[1].split(/\s+/).filter((t) => !/^\[/.test(t))[0] || "" : "";
    return { raw: v, from: fromM ? fromM[1] : "unknown", host: parHost, ip: ipM ? ipM[1] : "", by: byM ? byM[1] : "", date: dateM ? dateM[1].trim() : "" };
  }).reverse();
  const urls = [];
  (body.match(/https?:\/\/[^\s"'<>)\]]+/g) || []).forEach((u) => { const c = u.replace(/[.,;)]$/, ""); if (urls.indexOf(c) < 0) urls.push(c); });
  const hosts = [];
  urls.forEach((u) => { try { const hh = new URL(u).hostname; if (hh && hosts.indexOf(hh) < 0) hosts.push(hh); } catch (e) {} });
  const ips = [];
  (body.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach((x) => { if (ips.indexOf(x) < 0) ips.push(x); });
  const emails = [];
  (text.match(/[\w.+-]+@[\w-]+\.[\w.]+/g) || []).forEach((x) => { if (emails.indexOf(x) < 0) emails.push(x); });
  const hashes = [];
  (body.match(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/gi) || []).forEach((x) => { if (hashes.indexOf(x) < 0) hashes.push(x); });
  const anchors = [];
  const aRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]{3,80})</gi;
  let am;
  while ((am = aRe.exec(body)) !== null) anchors.push({ href: am[1], text: am[2].trim() });
  const authRaw = h("authentication-results") || h("received-spf") || "";
  const auth = {
    spf: (authRaw.match(/spf[=.:\s]+([a-z]+)/i) || [])[1] || "unknown",
    dkim: (authRaw.match(/dkim[=.:\s]+([a-z]+)/i) || [])[1] || "unknown",
    dmarc: (authRaw.match(/dmarc[=.:\s]+([a-z]+)/i) || [])[1] || "unknown"
  };
  const fromAddr = (h("from").match(/<([^>]+)>/) || [h("from").trim()])[0];
  const dispName = (h("from").split("<")[0] || "").replace(/["']/g, "").trim();
  const senderDomain = (fromAddr.split("@")[1] || "").toLowerCase();
  const xip = (h("x-originating-ip") || h("x-sender-ip") || "").replace(/[\[\]]/g, "").trim();
  const dateVal = h("date");
  const tzOffset = (dateVal.match(/([+-])(\d{2})(\d{2})\s*$/) || [])[0] || "";
  const charset = (h("content-type").match(/charset="?([\w-]+)"?/i) || [])[1] || "us-ascii";
  const attachments = [];
  const nRe = /name=["']([^"']+)["']/gi;
  let nm;
  while ((nm = nRe.exec(body)) !== null) attachments.push(nm[1]);
  const lower = body.toLowerCase();
  const headerList = Object.keys(headers).map((k) => ({ k: k, v: headers[k].join(" | ") }));
  return {
    raw: text, headers: headers, headerList: headerList,
    subject: h("subject"), from: h("from"), fromAddr: fromAddr, dispName: dispName, senderDomain: senderDomain,
    to: h("to"), date: dateVal, messageId: h("message-id"), returnPath: h("return-path"), xip: xip,
    received: received, hops: received.filter((r) => r.ip), urls: urls, hosts: hosts, ips: ips, emails: emails,
    hashes: hashes, anchors: anchors, auth: auth, body: body,
    bodyText: body.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
    tzOffset: tzOffset, charset: charset, attachments: attachments,
    keywordHits: URGENCY.filter((w) => lower.indexOf(w[0]) >= 0).map((w) => ({ w: w[0], s: w[1] })),
    htmlRatio: (body.indexOf("<html") >= 0 || body.indexOf("<table") >= 0 || body.indexOf("<div") >= 0) ? 1 : 0
  };
}

function analyzeEmail(p) {
  const f = [];
  const add = (id, label, detail, weight, tone, layer) => f.push({ id: id, label: label, detail: detail, weight: weight, tone: tone, layer: layer });
  if (p.auth.spf === "fail") add("spf", "SPF validation FAILED", "Sender domain " + p.senderDomain + " is not authorized by the sending host.", 16, "rd", "L1");
  else if (p.auth.spf === "pass") add("spf", "SPF validation passed", "Envelope sender is authorized for the domain.", -6, "gr", "L1");
  if (p.auth.dmarc === "fail" || p.auth.dmarc === "none") add("dmarc", "DMARC not aligned", "DMARC result '" + p.auth.dmarc + "' — policy alignment broken.", 12, "rd", "L1");
  if (p.auth.dkim === "none" || p.auth.dkim === "fail") add("dkim", "DKIM signature missing", "No cryptographic signing on the message body.", 7, "am", "L1");
  p.keywordHits.forEach((k) => add("kw:" + k.w, "Urgency cue: '" + k.w + "'", "Social-engineering pressure language detected in body.", k.s, "am", "L2"));
  p.hosts.forEach((host) => { const b = brandImpersonation(host); if (b) add("brand:" + host, "Lookalike domain → " + b.brand, host + " — " + b.why, 22, "rd", "L1"); });
  p.hosts.forEach((host) => { if (/\.(top|xyz|click|loan|work|gq|ml|buzz|live|support)$/.test(host)) add("tld:" + host, "High-risk TLD: " + host.split(".").pop(), "TLD has a >4x phishing concentration in URLhaus/OpenPhish.", 10, "rd", "L2"); });
  if (p.urls.some((u) => u.indexOf("@") >= 0)) add("urlat", "Credential-stuffing URL (@ token)", "URL contains a userinfo segment used to spoof the visible host.", 14, "rd", "L3");
  if (p.urls.some((u) => /^http:\/\//.test(u))) add("http", "Cleartext HTTP link", "Credential submission over unencrypted transport.", 6, "am", "L2");
  const ipUrl = p.urls.filter((u) => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u));
  if (ipUrl.length) add("ipurl", "Raw-IP URL destination", ipUrl[0], 13, "rd", "L2");
  p.anchors.forEach((a, i) => {
    try {
      const hrefHost = new URL(a.href).hostname;
      if (/[\w-]+\.[a-z]{2,}/i.test(a.text) && a.text.indexOf(hrefHost) < 0) add("mis" + i, "Anchor text / href mismatch", "Visible '" + a.text + "' != actual '" + hrefHost + "'", 15, "rd", "L3");
    } catch (e) {}
  });
  const freeMail = ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "mail.ru", "yandex.ru", "qq.com"].indexOf(p.senderDomain) >= 0;
  if (freeMail && /accounts|billing|invoice|payroll|treasury|it desk|helpdesk/i.test(p.dispName + " " + p.subject)) add("disp", "Display-name spoofing", "Free-mail domain '" + p.senderDomain + "' masquerading as '" + p.dispName + "'.", 14, "rd", "L3");
  if (p.returnPath && p.fromAddr && p.returnPath.replace(/[<>]/g, "").split("@")[1] !== p.senderDomain) add("rp", "Return-Path envelope mismatch", "Envelope " + p.returnPath + " != header From " + p.fromAddr + ".", 9, "am", "L3");
  if (p.attachments.some((a) => /\.(html|htm|svg|iso|img|lnk|js|vbs|docm|xlsm|zip|rar)$/i.test(a))) add("att", "High-risk attachment", p.attachments.join(", ") + " — common malware/phishing container.", 15, "rd", "L2");
  if (p.xip && !isPrivate(p.xip)) add("xip", "Webmail IP leak (X-Originating-IP)", "Client address exposed: " + p.xip + " — VPN-resistant attribution signal.", 4, "am", "L4");
  const extHops = p.hops.filter((x) => !isPrivate(x.ip));
  if (extHops.length > 4) add("hops", "Excessive routing hops", extHops.length + " external relays — typical of laundered / bulletproof infrastructure.", 6, "am", "L4");
  if (extHops.length) {
    const g = geoFor(extHops[0].ip);
    if (g && (g.type === "tor" || g.type === "vpn")) add("anon", g.type.toUpperCase() + " origin netblock", extHops[0].ip + " → " + g.org + " (" + g.country + ")", g.type === "tor" ? 18 : 10, "rd", "L4");
  }
  if (p.htmlRatio && p.bodyText.length < 400 && p.urls.length) add("thin", "Image/HTML-heavy, text-poor", "Low text density with multiple CTAs evades classical NLP filters.", 5, "am", "L3");
  if (/bitcoin|crypto wallet|monero|usdt/i.test(p.bodyText)) add("crypto", "Cryptocurrency payment demand", "Irreversible payment channel requested.", 12, "rd", "L2");

  const sum = (layer) => f.filter((x) => x.layer === layer).reduce((s, x) => s + x.weight, 0);
  const sig = clamp(sum("L1") * 1.9, 0, 100);
  const ml = clamp(sum("L2") * 2.6, 0, 100);
  const dl = clamp(sum("L3") * 3.1 + (p.keywordHits.length ? 12 : 0), 0, 100);
  const agents = {
    text: clamp(ml * 0.7 + p.keywordHits.length * 6 + (p.dispName && freeMail ? 20 : 0), 2, 99),
    url: clamp(f.filter((x) => /brand|tld|ipurl|mis|http|urlat/.test(x.id)).reduce((s, x) => s + x.weight, 0) * 3.4 + (p.urls.length ? 15 : 0), 2, 99),
    metadata: clamp(sig * 0.85 + (p.hops.length > 3 ? 18 : 6), 2, 99),
    adversarial: clamp((p.anchors.some((a) => /&#|%40|xn--/i.test(a.href)) ? 40 : 18) + (p.htmlRatio ? 22 : 8) + sig * 0.3, 2, 99)
  };
  const PPO_WEIGHTS = { text: 0.24, url: 0.31, metadata: 0.27, adversarial: 0.18 };
  const llm = Object.keys(agents).reduce((s, k) => s + agents[k] * PPO_WEIGHTS[k], 0);
  const score = Math.round(clamp(sig * 0.15 + ml * 0.2 + dl * 0.25 + llm * 0.4, 0, 99.4));
  const verdict = score >= 72 ? "MALICIOUS" : score >= 45 ? "SUSPICIOUS" : score >= 25 ? "LOW RISK" : "BENIGN";
  const severity = score >= 72 ? "critical" : score >= 45 ? "high" : score >= 25 ? "medium" : "low";
  f.sort((a, b) => b.weight - a.weight);
  return { findings: f, layers: { L1: Math.round(sig), L2: Math.round(ml), L3: Math.round(dl), L4: Math.round(llm) }, agents: agents, ppo: PPO_WEIGHTS, score: score, verdict: verdict, severity: severity };
}

const SENDER_HISTORY = {
  "billing@securepay-invoice.com": { city: "Singapore", country: "SG", lat: 1.35, lon: 103.82, ip: "103.224.182.250", ts: new Date(Date.now() - 3 * 3600 * 1000).toISOString() },
  "accounts@maersk-line.top": { city: "Copenhagen", country: "DK", lat: 55.68, lon: 12.57, ip: "91.215.85.14", ts: new Date(Date.now() - 9 * 3600 * 1000).toISOString() }
};

function attributeGeo(p) {
  const extHops = p.hops.filter((x) => !isPrivate(x.ip));
  const originIp = (p.xip && !isPrivate(p.xip)) ? p.xip : (extHops.length ? extHops[0].ip : "");
  const g = originIp ? geoFor(originIp) : null;
  if (!g) return { g: null, signals: [], confidence: 0, originIp: "", travel: null, infraHits: 0, forged: 0 };
  const hdrTz = p.tzOffset ? parseInt(p.tzOffset.slice(1, 3), 10) * (p.tzOffset.charAt(0) === "-" ? -1 : 1) : null;
  const tzMatch = hdrTz !== null && Math.abs(hdrTz - g.tz) <= 1;
  const langWords = { "zh-CN": "CN", "ru-RU": "RU", "pt-BR": "BR", "es-ES": "ES", "ar-SA": "SA", "id-ID": "ID", "vi-VN": "VN" };
  const cl = p.headers["content-language"];
  const langHint = (cl && cl[0]) ? cl[0] : (langWords[p.charset] || "");
  const infraHits = 3 + (hashStr(originIp) % 9);
  const forged = extHops.filter((x) => !x.by || !x.date).length;
  const signals = [
    { name: "Webmail IP leak", src: p.xip ? "X-Originating-IP" : "not present", vpnResistant: true, lr: p.xip ? 8.4 : 1.0, note: p.xip ? "Client address leaked in header" : "No leak — relying on relay chain" },
    { name: "Timezone offset", src: (p.tzOffset || "n/a") + " vs UTC" + (g.tz >= 0 ? "+" : "") + g.tz, vpnResistant: true, lr: hdrTz === null ? 1.2 : (tzMatch ? 3.1 : 0.55), note: tzMatch ? "Header offset consistent with claimed locale" : "Offset contradicts geo-locale — forged Date header" },
    { name: "Language fingerprint", src: langHint || "charset " + p.charset, vpnResistant: true, lr: (langHint && langHint === g.cc) ? 4.2 : (langHint ? 0.8 : 1.4), note: langHint ? (langHint === g.cc ? "Content locale matches netblock" : "Content locale != netblock") : "Neutral Latin content" },
    { name: "Infrastructure reuse", src: infraHits + " prior campaigns", vpnResistant: true, lr: infraHits > 6 ? 6.5 : (infraHits > 3 ? 3.4 : 1.3), note: "Graph centrality across historical cases" },
    { name: "Hop chain forgery", src: forged + " malformed Received", vpnResistant: false, lr: forged ? 4.8 : 1.1, note: forged ? "Received headers inconsistent — injected hop" : "Chain internally consistent" },
    { name: "VPN / exit node map", src: g.type.toUpperCase(), vpnResistant: false, lr: g.type === "tor" ? 9.0 : (g.type === "vpn" ? 5.2 : (g.type === "hosting" ? 2.6 : 1.0)), note: g.org },
    { name: "Authentication results", src: "SPF " + p.auth.spf + " / DMARC " + p.auth.dmarc, vpnResistant: false, lr: (p.auth.dmarc === "fail" || p.auth.spf === "fail") ? 3.9 : 0.9, note: "Alignment vs. sending netblock" },
    { name: "Webmail provider FP", src: g.type === "corporate" ? "Google/M365" : "self-hosted MTA", vpnResistant: true, lr: g.type === "corporate" ? 0.7 : 2.2, note: "Header signature clustering" }
  ];
  const prior = 0.02;
  const lrProduct = signals.reduce((s, x) => s * x.lr, 1);
  const post = clamp((prior * lrProduct) / (prior * lrProduct + (1 - prior)), 0.03, 0.965);
  const conf = Math.round(post * 1000) / 10;
  let travel = null;
  const prev = SENDER_HISTORY[p.fromAddr] || SENDER_HISTORY[p.senderDomain];
  if (prev) {
    const d = haversine(g, prev);
    const hrs = (Date.now() - new Date(prev.ts).getTime()) / 3600000;
    const kmh = Math.round(d / Math.max(0.05, hrs));
    travel = { prev: prev, distanceKm: d, hours: Math.round(hrs * 10) / 10, kmh: kmh, impossible: kmh > 900, now: g };
  }
  return { g: g, signals: signals, confidence: conf, originIp: g.ip, travel: travel, infraHits: infraHits, forged: forged };
}

const SAMPLE_EML = `Return-Path: <bounce@mail-securepay-invoice.com>
Delivered-To: j.whitaker@northwind-logistics.com
Received: from mail-securepay-invoice.com (ec2-54-212-19-88.us-west-2.compute.amazonaws.com [54.212.19.88])
        by mx.google.com with ESMTPS id t7-200a0b9f.1.1.6f.2025.06.11.02.14.33
        for <j.whitaker@northwind-logistics.com>; Wed, 11 Jun 2025 02:14:35 -0700 (PDT)
Received: from smtp-relay-7.vps-net.io (tor-exit-3.zwiebelfreunde.org [185.220.101.47])
        by mail-securepay-invoice.com (Postfix) with ESMTP id 8F3A21C0E9
        for <j.whitaker@northwind-logistics.com>; Wed, 11 Jun 2025 16:14:30 +0700 (+07)
Received: from localhost (localhost [127.0.0.1])
        by smtp-relay-7.vps-net.io (Postfix) with ESMTP id 2A91D40B; Wed, 11 Jun 2025 09:13:02 +0000 (UTC)
X-Originating-IP: [185.220.101.47]
Authentication-Results: mx.google.com; spf=fail (google.com: domain of bounce@mail-securepay-invoice.com does not designate 54.212.19.88 as permitted sender) smtp.mailfrom=bounce@mail-securepay-invoice.com; dkim=none; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=securepay-invoice.com
Received-SPF: fail (google.com: domain of bounce@mail-securepay-invoice.com does not designate 54.212.19.88 as permitted sender)
From: "SecurePay Billing Department" <billing@securepay-invoice.com>
To: j.whitaker@northwind-logistics.com
Subject: =?UTF-8?B?VVJHRU5UOiBPdmVyZHVlIEludm9pY2UgI0lOVi0yMDI1LTg4NDEgLSBBY2NvdW50IFN1c3BlbmRlZA==?=
Date: Wed, 11 Jun 2025 16:14:28 +0700
Message-ID: <9f2c1a.7b3e.4d81@mail-securepay-invoice.com>
Content-Type: multipart/mixed; boundary="----=_Part_8841"; charset="UTF-8"
MIME-Version: 1.0
Content-Language: zh-CN

------=_Part_8841
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>Dear Customer,</p>
<p>This is an <b>URGENT</b> final notice. Your supplier account with SecurePay will be
<b>suspended within 24 hours</b> due to an overdue invoice. Immediate action is required.</p>
<p>Invoice #INV-2025-8841 &mdash; Amount due: USD 48,920.00 &mdash; beneficiary account updated.</p>
<p><a href="http://185.220.101.47/verify?token=9f2c1a7b3e">https://securepay-invoice.com/account/verify</a></p>
<p><a href="http://securepay-verify-invoice.top/login?id=northwind">Sign in to Microsoft 365 Billing Portal</a></p>
<p>Please confirm your identity and arrange the wire transfer using the new SWIFT code
attached. Kindly act now to avoid service interruption.</p>
<p>Attachment: Invoice_8841.html<br/>SHA256: 5d41402abc4b2a76b9719d911017c592781003a4a0d0b7f4c2e1a9d6b8f03c11</p>
</body></html>
------=_Part_8841
Content-Type: text/html; name="Invoice_8841.html"
Content-Disposition: attachment; filename="Invoice_8841.html"

<html><body>redirect to payment portal</body></html>
------=_Part_8841--`;

/* ── mock fleet data ─────────────────────────────────────────────────────── */
const CATS = ["BEC / CEO Fraud", "Credential Phishing", "Malware Dropper", "Invoice Fraud", "MFA Fatigue", "Spam / Nuisance"];
const SEV = ["critical", "high", "medium", "low"];
const SUBJECTS = [
  ["URGENT: Overdue Invoice #INV-2025-8841 - Account Suspended", "billing@securepay-invoice.com", "Invoice Fraud"],
  ["Action required: verify your Microsoft 365 password", "no-reply@micros0ft-secure.top", "Credential Phishing"],
  ["Wire transfer authorization - board approval needed", "ceo.office@northwind-logistics.cc", "BEC / CEO Fraud"],
  ["New voicemail message (2) - transcribe attached", "voice@mail-notifier-service.xyz", "Malware Dropper"],
  ["DHL Shipment #8842901 - customs fee outstanding", "customs@dhl-express-billing.click", "Invoice Fraud"],
  ["Your Coinbase account: unusual sign-in attempt", "security@coinbase-alerts.live", "Credential Phishing"],
  ["Shared document: Q3-Forecast.xlsx requires sign-in", "share@docu-sign-portal.work", "Credential Phishing"],
  ["Payroll direct deposit change confirmation", "hr@northwind-payroll-update.top", "BEC / CEO Fraud"],
  ["Meeting notes + recording attached", "assistant@exec-calendar.buzz", "Malware Dropper"],
  ["Account statement June 2025 - review required", "statements@chase-secure-portal.xyz", "Credential Phishing"],
  ["Purchase order PO-99213 - updated banking details", "ap@supplier-maersk-line.top", "Invoice Fraud"],
  ["You have 3 pending approvals in DocuSign", "dse@esign-notify.gq", "Credential Phishing"],
  ["Netflix payment declined - update card", "billing@netflix-renewal.click", "Spam / Nuisance"],
  ["IT Helpdesk: mailbox quota exceeded", "itdesk@northwind-it-support.top", "MFA Fatigue"],
  ["Freight quote attached (ISO image)", "logistics@global-freight-vn.xyz", "Malware Dropper"],
  ["Contract renewal signature required today", "legal@contract-sign-portal.ml", "BEC / CEO Fraud"],
  ["Your Apple ID was used to sign in on Windows", "noreply@apple-id-verify.support", "Credential Phishing"],
  ["Crypto wallet KYC re-verification", "kyc@coinbase-wallet-check.top", "Credential Phishing"]
];
const IPS = Object.keys(GEO_DB).map((k) => k + "." + (5 + (hashStr(k) % 200)));
const RECIPIENTS = ["j.whitaker", "m.okafor", "l.chen", "s.rivera", "a.kowalski"];

const mkAlert = (i, opts) => {
  const o = opts || {};
  const s = SUBJECTS[i % SUBJECTS.length];
  const subject = s[0], sender = s[1], cat = s[2];
  const seed = hashStr(sender + i + (o.id || ""));
  const score = 30 + (seed % 68);
  const ip = IPS[seed % IPS.length];
  const g = geoFor(ip);
  const ts = o.ts || new Date(Date.now() - (i * 1000 * 60 * (7 + (seed % 90)))).toISOString();
  const iocs = [{ type: "ip", value: ip }, { type: "domain", value: sender.split("@")[1] }];
  if (seed % 2) iocs.push({ type: "url", value: "http://" + sender.split("@")[1] + "/verify?token=" + (seed % 99999) });
  return {
    id: o.id || ("ALT-" + String(91400 + i)), ts: ts, subject: subject, sender: sender,
    recipient: RECIPIENTS[seed % 5] + "@northwind-logistics.com",
    category: cat, score: score,
    severity: score >= 80 ? "critical" : score >= 62 ? "high" : score >= 42 ? "medium" : "low",
    verdict: score >= 72 ? "MALICIOUS" : score >= 45 ? "SUSPICIOUS" : "BENIGN",
    layers: {
      L1: clamp(score - 12 - (seed % 9), 4, 99),
      L2: clamp(score + (seed % 11) - 6, 4, 99),
      L3: clamp(score + (seed % 15) - 3, 4, 99),
      L4: clamp(score + (seed % 8), 4, 99)
    },
    agents: {
      text: clamp(score - 4 + (seed % 13), 3, 99),
      url: clamp(score + 8 - (seed % 11), 3, 99),
      metadata: clamp(score - 7 + (seed % 17), 3, 99),
      adversarial: clamp(score + 3 - (seed % 9), 3, 99)
    },
    ip: ip, geo: g,
    status: o.status || (i % 7 === 0 ? "closed" : (i % 3 === 0 ? "triaged" : "new")),
    tenant: "northwind", iocs: iocs, fresh: !!o.fresh
  };
};
const BASE_ALERTS = Array.from({ length: 18 }, (x, i) => mkAlert(i));
const TIMESERIES = Array.from({ length: 24 }, (x, i) => {
  const base = 120 + Math.sin(i / 3) * 60 + rnd(i * 3.1) * 70;
  return { h: pad(i % 24) + ":00", volume: Math.round(base + 900), threats: Math.round(base), blocked: Math.round(base * 0.93), benign: 900, latency: Math.round(110 + rnd(i) * 90) };
});
const CAT_DATA = CATS.map((c, i) => ({ name: c, value: [38, 27, 14, 11, 6, 4][i] }));
const LAYER_DATA = [
  { name: "L1 Signature", caught: 41 }, { name: "L2 Classical ML", caught: 23 },
  { name: "L3 Deep Learn", caught: 27 }, { name: "L4 LLM Agents", caught: 9 }
];
const RADAR_DATA = [
  { k: "Linguistic", v: 88 }, { k: "Behavioral", v: 74 }, { k: "Graph", v: 91 },
  { k: "Structural", v: 83 }, { k: "Header", v: 95 }, { k: "Reputation", v: 69 }
];
const CASES = [
  { id: "CASE-2291", title: "Invoice redirection campaign — 'SecurePay'", status: "investigating", priority: "P1", analyst: "M. Okafor", created: "2025-06-11T09:12:00Z", emails: 47, iocs: 23, actor: "TA-118 (Lagos / AMS exit)", confidence: 82 },
  { id: "CASE-2288", title: "M365 credential harvest via lookalike SSO", status: "triage", priority: "P1", analyst: "L. Chen", created: "2025-06-10T14:02:00Z", emails: 132, iocs: 41, actor: "TA-044 (Shenzhen)", confidence: 76 },
  { id: "CASE-2284", title: "BEC — fraudulent payroll direct-deposit change", status: "review", priority: "P2", analyst: "S. Rivera", created: "2025-06-09T07:41:00Z", emails: 12, iocs: 9, actor: "Unattributed", confidence: 58 },
  { id: "CASE-2277", title: "ISO/IMG malware dropper — logistics lures", status: "triage", priority: "P2", analyst: "A. Kowalski", created: "2025-06-07T22:18:00Z", emails: 63, iocs: 18, actor: "TA-207 (Kyiv VPS)", confidence: 71 },
  { id: "CASE-2265", title: "DocuSign brand abuse wave", status: "closed", priority: "P3", analyst: "M. Okafor", created: "2025-06-02T11:00:00Z", emails: 210, iocs: 57, actor: "TA-118", confidence: 91 },
  { id: "CASE-2258", title: "MFA fatigue push-bombing on finance team", status: "review", priority: "P1", analyst: "L. Chen", created: "2025-05-29T16:30:00Z", emails: 8, iocs: 6, actor: "TA-044", confidence: 64 }
];
const EVIDENCE = [
  { id: "EV-01", kind: "Raw .eml", name: "invoice_8841_original.eml", size: "48 KB", sha: "5d41402abc4b2a76b9719d911017c592781003a4a0d0b7f4c2e1a9d6b8f03c11", custodian: "ingest-imap-01" },
  { id: "EV-02", kind: "Attachment", name: "Invoice_8841.html", size: "12 KB", sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", custodian: "sandbox-runner-3" },
  { id: "EV-03", kind: "Header export", name: "received_chain.json", size: "6 KB", sha: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", custodian: "parser-svc" },
  { id: "EV-04", kind: "PCAP slice", name: "url_redirect_chain.pcap", size: "1.2 MB", sha: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", custodian: "link-resolver" },
  { id: "EV-05", kind: "Analyst note", name: "attribution_summary.md", size: "9 KB", sha: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", custodian: "m.okafor" }
];
const TIMELINE = [
  { ts: "2025-06-11T02:14:28Z", t: "Message composed", d: "Origin netblock 185.220.101.47 (Tor exit, AMS)", k: "signal" },
  { ts: "2025-06-11T02:14:30Z", t: "Relayed via smtp-relay-7.vps-net.io", d: "Hop 2 — malformed Received header", k: "hop" },
  { ts: "2025-06-11T02:14:35Z", t: "Delivered to mx.google.com", d: "SPF fail, DMARC fail, no DKIM", k: "auth" },
  { ts: "2025-06-11T02:14:35.214Z", t: "Layer 1 signature matched", d: "OpenPhish feed hit on securepay-verify-invoice.top", k: "detect" },
  { ts: "2025-06-11T02:14:35.488Z", t: "Layer 3 DistilBERT verdict", d: "Phishing confidence 0.9978", k: "detect" },
  { ts: "2025-06-11T02:14:36.020Z", t: "Multi-agent fusion complete", d: "5 agents, PPO-weighted score 91", k: "agent" },
  { ts: "2025-06-11T02:14:36.090Z", t: "Automated containment", d: "Message quarantined, 4 sibling mails recalled (68 ms)", k: "action" },
  { ts: "2025-06-11T09:12:00Z", t: "Case CASE-2291 opened", d: "Assigned to M. Okafor, priority P1", k: "case" }
];
const GRAPH_NODES = [
  { id: "j.whitaker", g: 0, type: "internal", weight: 42 },
  { id: "m.okafor", g: 0, type: "internal", weight: 31 },
  { id: "l.chen", g: 0, type: "internal", weight: 28 },
  { id: "s.rivera", g: 1, type: "vip", weight: 55 },
  { id: "a.kowalski", g: 1, type: "internal", weight: 22 },
  { id: "finance-grp", g: 1, type: "internal", weight: 37 },
  { id: "billing@securepay-invoice.com", g: 2, type: "suspect", weight: 61 },
  { id: "no-reply@micros0ft-secure.top", g: 2, type: "suspect", weight: 44 },
  { id: "ceo.office@northwind-logistics.cc", g: 2, type: "suspect", weight: 39 },
  { id: "customs@dhl-express-billing.click", g: 3, type: "external", weight: 18 },
  { id: "vendor@maersk.com", g: 3, type: "external", weight: 26 },
  { id: "bank@hsbc-corp.com", g: 3, type: "external", weight: 21 },
  { id: "hr@northwind-payroll-update.top", g: 2, type: "suspect", weight: 33 },
  { id: "itdesk@northwind-it-support.top", g: 2, type: "suspect", weight: 29 }
];
const GRAPH_EDGES = [
  ["j.whitaker", "billing@securepay-invoice.com", 9], ["j.whitaker", "m.okafor", 6], ["m.okafor", "l.chen", 5],
  ["s.rivera", "ceo.office@northwind-logistics.cc", 4], ["s.rivera", "finance-grp", 8], ["finance-grp", "billing@securepay-invoice.com", 7],
  ["a.kowalski", "customs@dhl-express-billing.click", 3], ["finance-grp", "bank@hsbc-corp.com", 6], ["finance-grp", "vendor@maersk.com", 5],
  ["l.chen", "no-reply@micros0ft-secure.top", 4], ["j.whitaker", "hr@northwind-payroll-update.top", 2], ["a.kowalski", "itdesk@northwind-it-support.top", 2],
  ["s.rivera", "j.whitaker", 7], ["m.okafor", "finance-grp", 4]
].map((e) => ({ s: e[0], t: e[1], w: e[2] }));
const IOC_LIST = [
  { type: "ip", value: "185.220.101.47", sev: "critical", src: "Tor Project / AbuseIPDB", seen: "2025-06-11", conf: 96, cases: 14 },
  { type: "domain", value: "securepay-verify-invoice.top", sev: "critical", src: "OpenPhish", seen: "2025-06-09", conf: 94, cases: 9 },
  { type: "url", value: "http://185.220.101.47/verify?token=9f2c1a7b3e", sev: "high", src: "URLhaus", seen: "2025-06-11", conf: 88, cases: 4 },
  { type: "sha256", value: "5d41402abc4b2a76b9719d911017c592781003a4a0d0b7f4c2e1a9d6b8f03c11", sev: "high", src: "VirusTotal 34/72", seen: "2025-06-10", conf: 81, cases: 6 },
  { type: "email", value: "billing@securepay-invoice.com", sev: "critical", src: "Internal + HIBP", seen: "2025-06-02", conf: 92, cases: 23 },
  { type: "domain", value: "micros0ft-secure.top", sev: "high", src: "URLscan.io", seen: "2025-06-08", conf: 79, cases: 7 },
  { type: "ip", value: "45.155.205.118", sev: "high", src: "AbuseIPDB (98 reports)", seen: "2025-06-05", conf: 85, cases: 11 },
  { type: "url", value: "https://dhl-express-billing.click/pay/8842901", sev: "medium", src: "OpenPhish", seen: "2025-06-07", conf: 66, cases: 3 },
  { type: "sha256", value: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", sev: "medium", src: "VirusTotal 12/71", seen: "2025-06-01", conf: 54, cases: 2 },
  { type: "email", value: "hr@northwind-payroll-update.top", sev: "critical", src: "Internal BEC watch", seen: "2025-06-10", conf: 90, cases: 5 },
  { type: "ip", value: "203.119.8.44", sev: "medium", src: "IPinfo / Recorded Future", seen: "2025-05-28", conf: 61, cases: 8 },
  { type: "domain", value: "northwind-it-support.top", sev: "high", src: "URLhaus", seen: "2025-06-09", conf: 77, cases: 4 }
];
const ROADMAP = [
  { phase: "Phase 1 — Foundation", months: "M1-3", progress: 100, items: [["IMAP/SMTP ingestion + parsing", 100], ["DistilBERT + Logistic Regression", 100], ["Alert console (<1 s)", 100], ["Immutable forensic archive", 100]] },
  { phase: "Phase 2 — Intelligence", months: "M4-6", progress: 82, items: [["Multi-signal Bayesian geolocation", 90], ["5-agent LLM framework", 85], ["5+ external threat feeds", 88], ["Investigation workbench", 65]] },
  { phase: "Phase 3 — Advanced", months: "M7-9", progress: 46, items: [["Adversarial training loop", 55], ["Social graph peer-group analysis", 60], ["Impossible-travel detection", 48], ["Automated response <100 ms", 22]] },
  { phase: "Phase 4 — Scale", months: "M10-12", progress: 12, items: [["Multi-tenant isolation (100+)", 20], ["HA deployment 99.99%", 15], ["Public API + webhooks", 12], ["Automated PDF reporting", 8]] }
];
const STACK = [
  ["Ingestion", "IMAP IDLE, SMTP, MTA hooks, imapflow"],
  ["Backend", "Python 3.12, FastAPI, async workers"],
  ["ML / DL", "PyTorch, TensorFlow, Transformers, Scikit-learn, XGBoost"],
  ["LLM", "Ollama (Qwen 2.5, Llama 3.1), OpenAI / Grok API"],
  ["Vector DB", "Chroma, pgvector"],
  ["Graph DB", "Neo4j"],
  ["Time-series", "TimescaleDB"],
  ["Search", "Elasticsearch"],
  ["Frontend", "React, Next.js, Tailwind CSS (v0 → Vercel)"],
  ["Infra", "Docker, Kubernetes, AWS / Azure / GCP"]
];
const KPIS = [
  ["Detection accuracy", ">97%", "98.4%", "gr"],
  ["False positive rate", "<3%", "1.9%", "gr"],
  ["False negative rate", "<0.5%", "0.31%", "gr"],
  ["Processing latency", "<200 ms", "142 ms", "cy"],
  ["Geolocation accuracy", ">50% country", "52.8%", "am"],
  ["System uptime", "99.99%", "99.994%", "gr"],
  ["Concurrent emails", "10,000/min", "11.2K/min", "vi"]
];
const REQUIRED_VARS = [
  { g: "Supabase (database)", vars: [["NEXT_PUBLIC_SUPABASE_URL", "Project URL", true], ["NEXT_PUBLIC_SUPABASE_ANON_KEY", "Client anon key", true], ["SUPABASE_SERVICE_ROLE_KEY", "Server-only key (never expose)", true], ["SUPABASE_BUCKET", "forensic-archive storage bucket", false]] },
  { g: "LLM / multi-agent", vars: [["OPENAI_API_KEY", "GPT-4o for Text/URL/Metadata/Adversarial agents", false], ["OLLAMA_BASE_URL", "http://localhost:11434 — local Qwen 2.5 / Llama 3.1", false], ["OLLAMA_MODEL", "qwen2.5:14b", false], ["EMBEDDING_MODEL", "text-embedding-3-small", false]] },
  { g: "Threat intelligence", vars: [["VIRUSTOTAL_API_KEY", "File / URL / domain reputation", true], ["ABUSEIPDB_API_KEY", "IP reputation + blacklist", true], ["IPINFO_TOKEN", "GeoIP, ASN, ISP", true], ["URLSCAN_API_KEY", "URL behaviour + screenshots", false], ["HIBP_API_KEY", "Breach intelligence", false], ["RECORDED_FUTURE_API_KEY", "Adversary tracking", false]] },
  { g: "Ingestion", vars: [["IMAP_HOST", "imap.mail-host.com", false], ["IMAP_PORT", "993", false], ["IMAP_USER", "collector@tenant.com", false], ["IMAP_PASS", "app password (vault)", false], ["MTA_WEBHOOK_SECRET", "SMTP inline inspection HMAC", false]] },
  { g: "Supporting stores", vars: [["DATABASE_URL", "TimescaleDB / pgvector", false], ["NEO4J_URI", "bolt://graph:7687", false], ["NEO4J_USER", "neo4j", false], ["NEO4J_PASSWORD", "graph password", false], ["ELASTICSEARCH_URL", "https://es:9200", false], ["REDIS_URL", "cache + rate limiting", false], ["SENTRY_DSN", "error tracking", false]] }
];

const SQL_SCHEMA = `-- == SentinelGrid - Supabase schema (paste into SQL Editor) ==
create extension if not exists "pgcrypto";
create extension if not exists "vector";        -- pgvector for embeddings

create table if not exists tenants (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null, name text not null,
  plan text default 'standard', created_at timestamptz default now()
);
create table if not exists emails (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references tenants(id) on delete cascade,
  message_id text, ts timestamptz, sender text, sender_domain text,
  recipient text, subject text, size_bytes int,
  raw_ref text,                    -- storage path in forensic-archive bucket
  sha256 text not null,            -- chain-of-custody hash
  body_text text, headers jsonb, attachments jsonb default '[]'::jsonb,
  embedding vector(1536), created_at timestamptz default now()
);
create index if not exists emails_ts_idx on emails using brin (ts);
create index if not exists emails_embedding_idx on emails using ivfflat (embedding vector_cosine_ops) with (lists = 100);

create table if not exists detections (
  id uuid primary key default gen_random_uuid(),
  email_id uuid references emails(id) on delete cascade,
  score numeric(5,2), verdict text, severity text,
  layer1 int, layer2 int, layer3 int, layer4 int,
  agents jsonb, ppo_weights jsonb, explain jsonb,
  model_version text, latency_ms int, created_at timestamptz default now()
);
create table if not exists alerts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references tenants(id), detection_id uuid references detections(id),
  email_id uuid references emails(id), category text, status text default 'new',
  assignee uuid, priority text default 'P3', created_at timestamptz default now(),
  closed_at timestamptz
);
create table if not exists hops (
  id bigserial primary key, email_id uuid references emails(id) on delete cascade,
  seq int, host text, ip inet, asn text, org text, country text, city text,
  lat numeric, lon numeric, node_type text, forged boolean default false, hop_ts timestamptz
);
create table if not exists geo_attributions (
  id uuid primary key default gen_random_uuid(),
  email_id uuid references emails(id) on delete cascade,
  origin_ip inet, country text, region text, city text, lat numeric, lon numeric,
  aci_confidence numeric(5,2), signals jsonb, vpn_detected boolean, tor_exit boolean,
  impossible_travel boolean, travel_kmh numeric, created_at timestamptz default now()
);
create table if not exists iocs (
  id uuid primary key default gen_random_uuid(),
  type text not null, value text not null, severity text, confidence int,
  first_seen timestamptz, last_seen timestamptz, sources jsonb default '[]'::jsonb,
  case_ids uuid[] default '{}', unique (type, value)
);
create table if not exists cases (
  id uuid primary key default gen_random_uuid(), tenant_id uuid references tenants(id),
  ref text unique, title text, status text default 'triage', priority text default 'P3',
  analyst uuid, actor_profile text, confidence int, scope jsonb,
  opened_at timestamptz default now(), closed_at timestamptz
);
create table if not exists case_evidence (
  id uuid primary key default gen_random_uuid(), case_id uuid references cases(id) on delete cascade,
  kind text, name text, size_bytes int, sha256 text not null,
  custodian text, collected_at timestamptz default now(), storage_path text, verified boolean default true
);
create table if not exists case_events (
  id bigserial primary key, case_id uuid references cases(id) on delete cascade,
  ts timestamptz default now(), kind text, title text, detail text, actor text
);
create table if not exists social_edges (
  id bigserial primary key, tenant_id uuid references tenants(id),
  src text, dst text, weight int, first_seen timestamptz, last_seen timestamptz,
  peer_group int, anomaly numeric(5,2), unique (src, dst)
);
create table if not exists reports (
  id uuid primary key default gen_random_uuid(), case_id uuid references cases(id),
  title text, format text default 'markdown', body text, generated_by uuid,
  generated_at timestamptz default now(), hash text
);
create table if not exists threat_feed_cache (
  key text primary key, feed text, payload jsonb, fetched_at timestamptz default now(),
  expires_at timestamptz
);
create table if not exists audit_log (
  id bigserial primary key, ts timestamptz default now(), actor text,
  action text, entity text, entity_id text, meta jsonb, prev_hash text, row_hash text
);

-- Row Level Security
alter table tenants enable row level security;
alter table emails enable row level security;
alter table detections enable row level security;
alter table alerts enable row level security;
alter table iocs enable row level security;
alter table cases enable row level security;
alter table case_evidence enable row level security;
alter table case_events enable row level security;
alter table audit_log enable row level security;

create policy "analysts write alerts" on alerts
  for all using ( auth.jwt() ->> 'role' in ('analyst','admin','lead') );
create policy "analysts read cases" on cases
  for select using ( auth.jwt() ->> 'role' in ('analyst','admin','lead','auditor') );

-- Realtime (SSE replacement in Supabase)
alter publication supabase_realtime add table alerts, detections, cases, iocs;

-- Storage bucket (immutable forensic archive)
insert into storage.buckets (id, name, public, file_size_limit)
values ('forensic-archive', 'forensic-archive', false, 52428800) on conflict do nothing;`;

/* ── styles (all motion = CSS keyframes, zero animation deps) ────────────── */
const CSS = `
@import url('https://cdn.jsdelivr.net/fontsource/css/inter@latest/index.css');
@import url('https://cdn.jsdelivr.net/fontsource/css/jetbrains-mono@latest/index.css');
*{box-sizing:border-box}
:root{--bg:#05080e;--p1:#0a101a;--p2:#0d1521;--p3:#111c2a;--ln:rgba(120,180,220,.14);--ln2:rgba(120,180,220,.28);
--tx:#e7f1f8;--mu:#8096a9;--cy:#22d3ee;--gr:#34d399;--am:#fbbf24;--rd:#fb7185;--vi:#a78bfa;--bl:#60a5fa}
html,body,#root{margin:0;height:100%;background:var(--bg);color:var(--tx);font-family:'Inter',system-ui,sans-serif;font-size:13px}
body{background-image:radial-gradient(900px 500px at 12% -8%,rgba(34,211,238,.09),transparent 60%),radial-gradient(800px 500px at 92% 0%,rgba(167,139,250,.08),transparent 60%)}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes slideIn{from{transform:translateX(102%)}to{transform:translateX(0)}}
@keyframes slideOut{from{transform:translateX(0)}to{transform:translateX(102%)}}
@keyframes popIn{from{opacity:0;transform:translate(-50%,-50%) scale(.94)}to{opacity:1;transform:translate(-50%,-50%) scale(1)}}
@keyframes toastIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
@keyframes rowIn{0%{background:rgba(251,113,133,.24)}100%{background:transparent}}
@keyframes dashFlow{to{stroke-dashoffset:-24}}
@keyframes sweep{0%{transform:translateX(-100%)}100%{transform:translateX(300%)}}
.fu{animation:fadeUp .3s ease both}
.fi{animation:fadeIn .3s ease both}
.rownew>td{animation:rowIn 3.4s ease-out both}
.edgeflow{stroke-dasharray:5 7;animation:dashFlow 1.8s linear infinite}
.app{display:flex;height:100vh;overflow:hidden}
.side{width:236px;flex:none;background:linear-gradient(180deg,#080d15,#060a11);border-right:1px solid var(--ln);display:flex;flex-direction:column;padding:14px 10px;gap:4px;overflow-y:auto}
.logo{display:flex;align-items:center;gap:10px;padding:6px 8px 16px}
.logo b{font-size:14px;letter-spacing:.4px}
.navbtn{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--mu);cursor:pointer;border:1px solid transparent;background:transparent;width:100%;text-align:left;font-size:12.5px;font-family:inherit;transition:.15s}
.navbtn:hover{color:var(--tx);background:rgba(34,211,238,.06)}
.navbtn.on{color:#dffaff;background:linear-gradient(90deg,rgba(34,211,238,.16),rgba(34,211,238,.03));border-color:rgba(34,211,238,.3);box-shadow:inset 2px 0 0 var(--cy)}
.navsec{font-size:9.5px;letter-spacing:1.4px;color:#4d6175;padding:14px 10px 5px;text-transform:uppercase}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.top{height:54px;flex:none;border-bottom:1px solid var(--ln);display:flex;align-items:center;gap:12px;padding:0 18px;background:rgba(8,13,21,.7)}
.body{flex:1;overflow-y:auto;padding:18px}
.body::-webkit-scrollbar,.side::-webkit-scrollbar,.scroll::-webkit-scrollbar{width:8px;height:8px}
.body::-webkit-scrollbar-thumb,.side::-webkit-scrollbar-thumb,.scroll::-webkit-scrollbar-thumb{background:#1b2836;border-radius:4px}
.grid{display:grid;gap:12px}
.panel{background:linear-gradient(180deg,var(--p2),var(--p1));border:1px solid var(--ln);border-radius:12px;position:relative;overflow:hidden}
.panel:before{content:'';position:absolute;inset:0 0 auto;height:1px;background:linear-gradient(90deg,transparent,rgba(34,211,238,.5),transparent)}
.ph{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 14px;border-bottom:1px solid var(--ln);flex-wrap:wrap}
.ph h3{margin:0;font-size:12px;letter-spacing:.6px;text-transform:uppercase;color:#b9cede;font-weight:600}
.pb{padding:14px}
.kpi{padding:13px 14px}
.kpi .l{font-size:10px;letter-spacing:1px;color:var(--mu);text-transform:uppercase}
.kpi .v{font-size:24px;font-weight:650;margin-top:5px;letter-spacing:-.5px}
.kpi .d{font-size:10.5px;margin-top:4px;color:var(--mu)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:600;letter-spacing:.5px;border:1px solid;text-transform:uppercase;white-space:nowrap}
.b-rd{color:#ffc2cd;border-color:rgba(251,113,133,.4);background:rgba(251,113,133,.12)}
.b-am{color:#ffe4a8;border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.1)}
.b-gr{color:#aef3d4;border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.1)}
.b-cy{color:#b6f2ff;border-color:rgba(34,211,238,.4);background:rgba(34,211,238,.1)}
.b-vi{color:#ddd0ff;border-color:rgba(167,139,250,.4);background:rgba(167,139,250,.1)}
.b-mu{color:#b6c6d3;border-color:rgba(140,170,195,.3);background:rgba(140,170,195,.08)}
.btn{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border-radius:8px;border:1px solid var(--ln2);background:var(--p3);color:var(--tx);cursor:pointer;font-size:11.5px;font-family:inherit;font-weight:550;transition:.15s;white-space:nowrap}
.btn:hover{border-color:rgba(34,211,238,.55);background:#16283a}
.btn.p{background:linear-gradient(135deg,#0e7490,#155e75);border-color:#22d3ee;color:#eafeff}
.btn.d{border-color:rgba(251,113,133,.4);color:#ffc2cd}
.btn.sm{padding:4px 9px;font-size:10.5px}
.btn:disabled{opacity:.4;cursor:not-allowed}
table{width:100%;border-collapse:collapse}
th{font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--mu);text-align:left;padding:8px 10px;border-bottom:1px solid var(--ln);font-weight:600;position:sticky;top:0;background:#0b1220;z-index:2}
td{padding:9px 10px;border-bottom:1px solid rgba(120,180,220,.07);vertical-align:middle;font-size:12px}
tr.cl{cursor:pointer;transition:.12s}
tr.cl:hover td{background:rgba(34,211,238,.05)}
.scroll{overflow:auto;max-height:100%}
.inp{width:100%;background:#070c14;border:1px solid var(--ln);border-radius:8px;padding:9px 11px;color:var(--tx);font-family:'JetBrains Mono',monospace;font-size:11.5px;resize:vertical;outline:none}
.inp:focus{border-color:rgba(34,211,238,.55)}
.inps{background:#070c14;border:1px solid var(--ln);border-radius:8px;padding:7px 10px;color:var(--tx);font-family:inherit;font-size:12px;outline:none}
.inps:focus{border-color:rgba(34,211,238,.5)}
.bar{height:6px;border-radius:4px;background:#131f2d;overflow:hidden}
.bar>i{display:block;height:100%;border-radius:4px;transition:width .6s cubic-bezier(.2,.8,.2,1)}
.tabs{display:flex;gap:3px;padding:3px;background:#080e17;border:1px solid var(--ln);border-radius:10px}
.tab{padding:6px 12px;border-radius:7px;font-size:11.5px;color:var(--mu);cursor:pointer;border:0;background:transparent;font-family:inherit;font-weight:550;transition:.15s}
.tab.on{background:linear-gradient(180deg,#16293b,#101d2a);color:#dffaff}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(720px,94vw);background:#070c14;border-left:1px solid var(--ln2);z-index:60;display:flex;flex-direction:column;box-shadow:-30px 0 80px rgba(0,0,0,.6);animation:slideIn .28s cubic-bezier(.2,.8,.2,1) both}
.drawer.out{animation:slideOut .22s ease-in both}
.ov{position:fixed;inset:0;background:rgba(2,5,10,.72);z-index:55;animation:fadeIn .2s both}
.ov.out{animation:fadeIn .2s reverse both}
.kv{display:grid;grid-template-columns:132px 1fr;gap:5px 12px;font-size:11.5px}
.kv>div:nth-child(odd){color:var(--mu)}
.chip{padding:3px 8px;border-radius:6px;background:#101b28;border:1px solid var(--ln);font-size:10.5px;font-family:'JetBrains Mono',monospace;color:#a9c3d4;display:inline-block;margin:2px 3px 2px 0}
.hop{display:grid;grid-template-columns:26px 1fr auto;gap:10px;padding:9px 0;border-bottom:1px dashed rgba(120,180,220,.12)}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.spin{animation:spin 1s linear infinite;display:inline-flex}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:90;display:flex;flex-direction:column;gap:8px;align-items:center}
.tt{background:#0d1a26;border:1px solid rgba(34,211,238,.4);color:#dffaff;padding:10px 16px;border-radius:10px;font-size:12px;box-shadow:0 12px 40px rgba(0,0,0,.6);display:flex;gap:9px;align-items:center;animation:toastIn .25s ease both}
.modal{position:fixed;top:50%;left:50%;width:min(480px,92vw);background:#0a121d;border:1px solid rgba(34,211,238,.35);border-radius:14px;padding:18px;z-index:70;box-shadow:0 30px 80px rgba(0,0,0,.7);animation:popIn .22s cubic-bezier(.2,.8,.2,1) both}
code.blk{display:block;background:#060b12;border:1px solid var(--ln);border-radius:10px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:10.8px;line-height:1.65;color:#9fd3e0;white-space:pre;overflow:auto;max-height:420px}
.sw{width:34px;height:19px;border-radius:12px;background:#1a2735;border:1px solid var(--ln2);position:relative;cursor:pointer;flex:none;transition:.2s}
.sw>i{position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:#5b7183;transition:.2s}
.sw.on{background:rgba(34,211,238,.25);border-color:var(--cy)}
.sw.on>i{left:16px;background:var(--cy)}
.kan{display:grid;grid-template-columns:repeat(4,minmax(230px,1fr));gap:12px;align-items:start}
.kcard{background:var(--p2);border:1px solid var(--ln);border-radius:10px;padding:10px;cursor:pointer;transition:.15s}
.kcard:hover{border-color:rgba(34,211,238,.45)}
.mrow{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(120,180,220,.07)}
.grad{background:linear-gradient(90deg,var(--cy),var(--vi));-webkit-background-clip:text;background-clip:text;color:transparent}
.scan{position:absolute;inset:0;pointer-events:none;overflow:hidden}
.scan:after{content:'';position:absolute;top:0;bottom:0;width:34%;background:linear-gradient(90deg,transparent,rgba(34,211,238,.07),transparent);animation:sweep 5.5s linear infinite}
@media (max-width:1100px){.side{width:62px}.side .lbl,.side .navsec{display:none}.kan{grid-template-columns:1fr 1fr}}
`;

/* ── primitives ──────────────────────────────────────────────────────────── */
const TONE = { rd: "#fb7185", am: "#fbbf24", gr: "#34d399", cy: "#22d3ee", vi: "#a78bfa", bl: "#60a5fa", mu: "#8096a9" };
const sevTone = (s) => (s === "critical" ? "rd" : s === "high" ? "am" : s === "medium" ? "cy" : "mu");

function Icon({ n, s = 15, c = "currentColor" }) {
  const P = {
    shield: "M12 2l8 3.5v6c0 5-3.4 9.3-8 10.5-4.6-1.2-8-5.5-8-10.5v-6L12 2z",
    bell: "M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0",
    mail: "M3 5h18v14H3zM3 6l9 7 9-7",
    globe: "M12 3a9 9 0 100 18 9 9 0 000-18M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18",
    graph: "M6 6h.01M18 6h.01M12 18h.01M6 6l6 12M18 6l-6 12M6 6h12",
    folder: "M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z",
    search: "M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3",
    doc: "M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5zM14 3v5h5",
    layers: "M12 2l9 5-9 5-9-5 9-5zM3 12l9 5 9-5M3 17l9 5 9-5",
    gear: "M12 15.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM19 12a7 7 0 00-.2-1.6l2-1.5-2-3.4-2.3 1a7 7 0 00-2.8-1.6L13.3 2h-2.6l-.4 2.9a7 7 0 00-2.8 1.6l-2.3-1-2 3.4 2 1.5a7 7 0 000 3.2l-2 1.5 2 3.4 2.3-1a7 7 0 002.8 1.6l.4 2.9h2.6l.4-2.9a7 7 0 002.8-1.6l2.3 1 2-3.4-2-1.5c.1-.5.2-1 .2-1.6z",
    bolt: "M13 2L4 14h7l-1 8 9-12h-7l1-8z",
    play: "M6 4l14 8-14 8V4z",
    down: "M12 3v12m0 0l-4-4m4 4l4-4M4 21h16",
    copy: "M9 9h10v10H9zM5 15V5h10",
    check: "M20 6L9 17l-5-5",
    x: "M18 6L6 18M6 6l12 12",
    che: "M9 6l6 6-6 6",
    cpu: "M6 6h12v12H6zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4",
    lock: "M5 11h14v10H5zM8 11V7a4 4 0 118 0v4",
    db: "M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
    eye: "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7zM12 15a3 3 0 100-6 3 3 0 000 6z",
    plus: "M12 5v14M5 12h14",
    flag: "M5 21V4h9l-1 3h6l-2 5 2 5h-9l1-3H5",
    target: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 16a4 4 0 100-8 4 4 0 000 8zM12 13a1 1 0 100-2 1 1 0 000 2z",
    refresh: "M21 12a9 9 0 11-3-6.7M21 3v6h-6",
    print: "M6 9V3h12v6M6 18H4v-6h16v6h-2M8 14h8v7H8z",
    warn: "M12 3l10 18H2L12 3zM12 9v5M12 17h.01"
  };
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d={P[n] || P.shield} />
    </svg>
  );
}
const Badge = ({ tone = "mu", children, dot }) => (
  <span className={"badge b-" + tone}>
    {dot ? <span className="dot" style={{ background: TONE[tone], width: 6, height: 6 }} /> : null}
    {children}
  </span>
);
const Panel = ({ title, sub, right, children, style, bodyStyle, className }) => (
  <div className={"panel " + (className || "")} style={style}>
    {(title || right) ? (
      <div className="ph">
        <div>
          <h3>{title}</h3>
          {sub ? <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 2 }}>{sub}</div> : null}
        </div>
        {right}
      </div>
    ) : null}
    <div className="pb" style={bodyStyle}>{children}</div>
  </div>
);
const Meter = ({ v, tone = "cy", h = 6 }) => (
  <div className="bar" style={{ height: h }}>
    <i style={{ width: clamp(v, 0, 100) + "%", background: "linear-gradient(90deg," + TONE[tone] + "66," + TONE[tone] + ")" }} />
  </div>
);
const Stat = ({ label, value, delta, tone = "cy", icon, sub, delay = 0 }) => (
  <div className="panel kpi fu" style={{ animationDelay: delay + "ms" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
      <div className="l">{label}</div>
      <span style={{ color: TONE[tone], opacity: 0.85, display: "inline-flex" }}><Icon n={icon || "shield"} s={15} /></span>
    </div>
    <div className="v" style={{ color: TONE[tone] }}>{value}</div>
    <div className="d">
      {sub}
      {delta ? <span style={{ color: delta.charAt(0) === "-" ? TONE.gr : TONE[tone], marginLeft: sub ? 8 : 0 }}>{delta}</span> : null}
    </div>
  </div>
);
const Th = ({ children }) => <th>{children}</th>;
const Empty = ({ t = "No records" }) => <div style={{ padding: 26, textAlign: "center", color: "var(--mu)", fontSize: 12 }}>{t}</div>;

function useCountUp(target, dur = 900) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf;
    const st = (typeof performance !== "undefined" ? performance.now() : Date.now());
    const step = (t) => {
      const p = clamp((t - st) / dur, 0, 1);
      setV(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, dur]);
  return v;
}
const Counter = ({ to, dec = 0, suffix = "" }) => { const v = useCountUp(to); return <span>{v.toFixed(dec)}{suffix}</span>; };

const copy = async (t) => {
  try { await navigator.clipboard.writeText(t); return true; }
  catch (e) {
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e2) {}
    ta.remove();
    return true;
  }
};
const download = (name, text, type = "text/markdown") => {
  const b = new Blob([text], { type: type });
  const u = URL.createObjectURL(b);
  const a = document.createElement("a");
  a.href = u; a.download = name; a.click();
  URL.revokeObjectURL(u);
};
async function sha256(str) {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) {
    let out = "";
    for (let i = 0; i < 8; i++) out += String(hashStr(str + i)).padStart(8, "0");
    return out.slice(0, 64);
  }
}

/* ── world map ───────────────────────────────────────────────────────────── */
function WorldMap({ points = [], arcs = [], selected, onSelect, height = 330 }) {
  return (
    <div className="fi" style={{ position: "relative", borderRadius: 10, overflow: "hidden", border: "1px solid var(--ln)", background: "radial-gradient(700px 340px at 50% 40%,#0a1a26,#05090f 75%)" }}>
      <svg viewBox="0 0 1000 500" preserveAspectRatio="none" style={{ width: "100%", height: height, display: "block" }}>
        <defs>
          <linearGradient id="land" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0f2a33" /><stop offset="100%" stopColor="#0a1c25" />
          </linearGradient>
        </defs>
        {Array.from({ length: 19 }, (x, i) => (
          <line key={"v" + i} x1={(i * 1000) / 18} y1="0" x2={(i * 1000) / 18} y2="500" stroke="rgba(90,160,200,.055)" strokeWidth="1" />
        ))}
        {Array.from({ length: 9 }, (x, i) => (
          <line key={"h" + i} x1="0" y1={(i * 500) / 8} x2="1000" y2={(i * 500) / 8} stroke="rgba(90,160,200,.055)" strokeWidth="1" />
        ))}
        {MAP_PATHS.map((d, i) => (
          <path key={i} d={d} fill="url(#land)" stroke="rgba(34,211,238,.42)" strokeWidth="1.1" strokeLinejoin="round" />
        ))}
        {arcs.map((a, i) => {
          const p1 = proj(a.from.lon, a.from.lat);
          const p2 = proj(a.to.lon, a.to.lat);
          const mx = (p1[0] + p2[0]) / 2;
          const my = (p1[1] + p2[1]) / 2 - Math.abs(p2[0] - p1[0]) * 0.22 - 14;
          return (
            <path key={"a" + i} className="edgeflow"
              d={"M" + p1[0] + "," + p1[1] + " Q" + mx + "," + my + " " + p2[0] + "," + p2[1]}
              fill="none" stroke={a.tone === "rd" ? "rgba(251,113,133,.8)" : "rgba(34,211,238,.65)"} strokeWidth={a.w || 1.4} />
          );
        })}
        {points.map((p, i) => {
          const c = proj(p.lon, p.lat);
          const col = TONE[p.tone || "rd"];
          const on = selected === p.id;
          return (
            <g key={"p" + i} style={{ cursor: "pointer" }} onClick={() => onSelect && onSelect(p)}>
              <circle cx={c[0]} cy={c[1]} r={on ? 16 : 11} fill={col} opacity="0.13" />
              <circle cx={c[0]} cy={c[1]} r={on ? 6.5 : 4} fill={col} stroke="#05080e" strokeWidth="1.2" />
              {p.pulse ? (
                <circle cx={c[0]} cy={c[1]} r="5" fill="none" stroke={col} strokeWidth="1.2" opacity="0.8">
                  <animate attributeName="r" from="5" to="20" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" />
                </circle>
              ) : null}
              {on ? <text x={c[0] + 10} y={c[1] - 8} fill="#dffaff" fontSize="11" fontFamily="JetBrains Mono, monospace">{p.label}</text> : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ── supabase hook ───────────────────────────────────────────────────────── */
function useSupabase() {
  const [state, setState] = useState({ status: "idle", msg: "", client: null, tables: [] });
  const [url, setUrl] = useState(cfgGet("NEXT_PUBLIC_SUPABASE_URL"));
  const [key, setKey] = useState(cfgGet("NEXT_PUBLIC_SUPABASE_ANON_KEY"));

  const connect = useCallback(async (u, k) => {
    const su = u || url;
    const sk = k || key;
    if (!su || !sk) {
      setState({ status: "demo", msg: "No Supabase credentials — running on local demo data", client: null, tables: [] });
      return null;
    }
    setState({ status: "connecting", msg: "Loading supabase-js…", client: null, tables: [] });
    try {
      if (!window.supabase) {
        await new Promise((res, rej) => {
          const sc = document.createElement("script");
          sc.src = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js";
          sc.onload = res;
          sc.onerror = () => rej(new Error("supabase-js CDN blocked"));
          document.head.appendChild(sc);
        });
      }
      const client = window.supabase.createClient(su, sk);
      const probes = ["emails", "alerts", "cases", "iocs", "detections"];
      const found = [];
      let lastMsg = "";
      for (let i = 0; i < probes.length; i++) {
        const r = await client.from(probes[i]).select("*", { head: true, count: "exact" });
        if (!r.error) found.push(probes[i]);
        else lastMsg = r.error.message;
      }
      if (found.length) setState({ status: "connected", msg: "Connected — tables: " + found.join(", "), client: client, tables: found });
      else setState({ status: "partial", msg: "Connected, but no tables yet (" + lastMsg + "). Run the schema SQL.", client: client, tables: [] });
      return client;
    } catch (e) {
      setState({ status: "error", msg: String(e.message || e), client: null, tables: [] });
      return null;
    }
  }, [url, key]);

  useEffect(() => { connect(url, key); }, []);

  const save = (u, k) => {
    cfgSet("NEXT_PUBLIC_SUPABASE_URL", u);
    cfgSet("NEXT_PUBLIC_SUPABASE_ANON_KEY", k);
    setUrl(u); setKey(k);
  };
  return { status: state.status, msg: state.msg, client: state.client, tables: state.tables, url: url, key: key, connect: connect, save: save };
}

/* ══════════════════════════ PAGES ══════════════════════════ */

function Overview({ alerts, goto, processed }) {
  const threats = alerts.filter((a) => a.verdict === "MALICIOUS").length;
  const crit = alerts.filter((a) => a.severity === "critical").length;
  const avg = Math.round(alerts.reduce((s, a) => s + a.score, 0) / Math.max(1, alerts.length));
  const geoPoints = alerts.slice(0, 12).map((a) => ({
    id: a.id, lon: a.geo.lon, lat: a.geo.lat,
    label: a.geo.city + " · " + a.geo.country,
    tone: a.severity === "critical" ? "rd" : (a.severity === "high" ? "am" : "cy"),
    pulse: a.severity === "critical"
  }));
  return (
    <div className="grid fu">
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(178px,1fr))" }}>
        <Stat label="Emails processed / 24h" value={<Counter to={processed} />} sub={fmt(processed) + " cumulative · "} delta="+8.4%" tone="cy" icon="mail" delay={0} />
        <Stat label="Threats detected" value={<Counter to={threats} />} sub="in current window · " delta="+12%" tone="rd" icon="shield" delay={40} />
        <Stat label="Critical alerts" value={<Counter to={crit} />} sub="P1 requiring triage" tone="am" icon="warn" delay={80} />
        <Stat label="Detection accuracy" value={<Counter to={98.4} dec={1} suffix="%" />} sub="target >97% · " delta="+0.6" tone="gr" icon="target" delay={120} />
        <Stat label="Mean latency" value={<Counter to={142} suffix=" ms" />} sub="target <200 ms" tone="vi" icon="bolt" delay={160} />
        <Stat label="Avg risk score" value={<Counter to={avg} />} sub="fleet-wide, 0-100" tone="bl" icon="cpu" delay={200} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.55fr 1fr" }}>
        <Panel title="Threat volume & containment — 24h" sub="Layered detection throughput vs. blocked" right={<Badge tone="gr" dot>Live</Badge>} className="scan">
          <div style={{ height: 216 }}>
            <ResponsiveContainer>
              <AreaChart data={TIMESERIES} margin={{ top: 4, right: 6, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="gT" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb7185" stopOpacity={0.55} /><stop offset="100%" stopColor="#fb7185" stopOpacity={0} /></linearGradient>
                  <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.4} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(120,180,220,.08)" vertical={false} />
                <XAxis dataKey="h" tick={{ fill: "#6f8698", fontSize: 10 }} axisLine={false} tickLine={false} interval={3} />
                <YAxis tick={{ fill: "#6f8698", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0b1420", border: "1px solid rgba(34,211,238,.3)", borderRadius: 8, fontSize: 11 }} labelStyle={{ color: "#dffaff" }} />
                <Legend wrapperStyle={{ fontSize: 10.5 }} />
                <Area type="monotone" dataKey="threats" name="Threats" stroke="#fb7185" fill="url(#gT)" strokeWidth={2} isAnimationActive={false} />
                <Area type="monotone" dataKey="blocked" name="Auto-contained" stroke="#34d399" fill="none" strokeWidth={1.6} strokeDasharray="4 3" isAnimationActive={false} />
                <Area type="monotone" dataKey="latency" name="Latency (ms)" stroke="#22d3ee" fill="url(#gB)" strokeWidth={1.6} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Attack category mix" sub="rolling 7-day distribution" bodyStyle={{ padding: 6 }}>
          <div style={{ height: 232 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={CAT_DATA} dataKey="value" innerRadius={52} outerRadius={82} paddingAngle={3} stroke="#0a101a" isAnimationActive={false}>
                  {CAT_DATA.map((e, i) => <Cell key={i} fill={["#fb7185", "#fbbf24", "#a78bfa", "#22d3ee", "#60a5fa", "#34d399"][i]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#0b1420", border: "1px solid rgba(34,211,238,.3)", borderRadius: 8, fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 10, lineHeight: "16px" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1.25fr" }}>
        <Panel title="Layer contribution" sub="% of threats caught per layer">
          <div style={{ height: 190 }}>
            <ResponsiveContainer>
              <BarChart data={LAYER_DATA} layout="vertical" margin={{ left: 26, right: 10, top: 2, bottom: 0 }}>
                <CartesianGrid stroke="rgba(120,180,220,.08)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#6f8698", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#9db4c4", fontSize: 10 }} axisLine={false} tickLine={false} width={74} />
                <Tooltip cursor={{ fill: "rgba(34,211,238,.06)" }} contentStyle={{ background: "#0b1420", border: "1px solid rgba(34,211,238,.3)", borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="caught" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                  {LAYER_DATA.map((e, i) => <Cell key={i} fill={["#60a5fa", "#22d3ee", "#a78bfa", "#fb7185"][i]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Feature families" sub="model explainability coverage">
          <div style={{ height: 190 }}>
            <ResponsiveContainer>
              <RadarChart data={RADAR_DATA} outerRadius={68}>
                <PolarGrid stroke="rgba(120,180,220,.15)" />
                <PolarAngleAxis dataKey="k" tick={{ fill: "#8aa2b4", fontSize: 9.5 }} />
                <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} />
                <Radar dataKey="v" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.32} isAnimationActive={false} />
                <Tooltip contentStyle={{ background: "#0b1420", border: "1px solid rgba(34,211,238,.3)", borderRadius: 8, fontSize: 11 }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Global threat origins" sub="last 12 attributed senders" right={<button className="btn sm" onClick={() => goto("geo")}>Open map <Icon n="che" s={12} /></button>} bodyStyle={{ padding: 8 }}>
          <WorldMap points={geoPoints} height={196} />
        </Panel>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.4fr 1fr" }}>
        <Panel title="Live alert stream" sub="auto-refreshing from detection bus" right={<button className="btn sm" onClick={() => goto("alerts")}>Alert console <Icon n="che" s={12} /></button>} bodyStyle={{ padding: 0 }}>
          <div className="scroll" style={{ maxHeight: 250 }}>
            <table>
              <thead><tr><Th>Time</Th><Th>Subject</Th><Th>Sender</Th><Th>Origin</Th><Th>Score</Th><Th>Verdict</Th></tr></thead>
              <tbody>
                {alerts.slice(0, 9).map((a) => (
                  <tr className={"cl" + (a.fresh ? " rownew" : "")} key={a.id} onClick={() => goto("alerts", a.id)}>
                    <td className="mono" style={{ color: "var(--mu)", fontSize: 11 }}>{ago(a.ts)}</td>
                    <td style={{ maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.subject}</td>
                    <td className="mono" style={{ fontSize: 10.5, color: "#9db4c4" }}>{a.sender}</td>
                    <td style={{ fontSize: 11 }}>{a.geo.country} <span style={{ color: "var(--mu)" }}>· {a.geo.type}</span></td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 7, width: 92 }}>
                        <span className="mono" style={{ fontSize: 11, color: TONE[sevTone(a.severity)] }}>{a.score}</span>
                        <div style={{ flex: 1 }}><Meter v={a.score} tone={sevTone(a.severity)} h={4} /></div>
                      </div>
                    </td>
                    <td><Badge tone={a.verdict === "MALICIOUS" ? "rd" : (a.verdict === "SUSPICIOUS" ? "am" : "gr")}>{a.verdict}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="Top indicators" sub="cross-case IOC frequency" right={<button className="btn sm" onClick={() => goto("ioc")}>Intel <Icon n="che" s={12} /></button>}>
          {IOC_LIST.slice(0, 6).map((i) => (
            <div className="mrow" key={i.value}>
              <span className="dot" style={{ background: TONE[sevTone(i.sev)] }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{i.value}</div>
                <div style={{ fontSize: 10, color: "var(--mu)" }}>{i.type.toUpperCase()} · {i.src} · {i.cases} cases</div>
              </div>
              <Badge tone={sevTone(i.sev)}>{i.conf}</Badge>
            </div>
          ))}
        </Panel>
      </div>

      <Panel title="Key performance targets" sub="SLA tracking vs. architecture spec">
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(210px,1fr))", gap: 10 }}>
          {KPIS.map((k) => (
            <div key={k[0]} style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 9, padding: 10 }}>
              <div style={{ fontSize: 10, color: "var(--mu)", textTransform: "uppercase", letterSpacing: 0.8 }}>{k[0]}</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginTop: 5 }}>
                <b style={{ fontSize: 16, color: TONE[k[3]] }}>{k[2]}</b>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--mu)" }}>target {k[1]}</span>
              </div>
              <div style={{ marginTop: 7 }}><Meter v={92} tone={k[3]} h={4} /></div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function AlertConsole({ alerts, setAlerts, open, live, setLive, toast }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [st, setSt] = useState("all");
  const list = alerts.filter((a) => {
    if (sev !== "all" && a.severity !== sev) return false;
    if (st !== "all" && a.status !== st) return false;
    if (q && (a.subject + a.sender + a.id + a.category).toLowerCase().indexOf(q.toLowerCase()) < 0) return false;
    return true;
  });
  const setStatus = (id, s) => {
    setAlerts((p) => p.map((a) => (a.id === id ? Object.assign({}, a, { status: s }) : a)));
    toast("Alert " + id + " → " + s);
  };
  return (
    <Panel className="fu" title="Alert console" sub={list.length + " of " + alerts.length + " alerts · real-time detection bus"}
      right={
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input className="inps" placeholder="Search subject / sender / ID…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 210 }} />
          <select className="inps" value={sev} onChange={(e) => setSev(e.target.value)}>
            {["all"].concat(SEV).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="inps" value={st} onChange={(e) => setSt(e.target.value)}>
            {["all", "new", "triaged", "investigating", "closed"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <div className={"sw" + (live ? " on" : "")} onClick={() => setLive(!live)}><i /></div>
            <span style={{ fontSize: 11, color: "var(--mu)" }}>Live feed</span>
          </div>
        </div>
      } bodyStyle={{ padding: 0 }}>
      <div className="scroll" style={{ maxHeight: "calc(100vh - 218px)" }}>
        <table>
          <thead><tr><Th>Alert</Th><Th>Subject</Th><Th>Sender</Th><Th>Category</Th><Th>Layers</Th><Th>Geo origin</Th><Th>Risk</Th><Th>Status</Th><Th></Th></tr></thead>
          <tbody>
            {list.map((a) => (
              <tr className={"cl" + (a.fresh ? " rownew" : "")} key={a.id} onClick={() => open(a)}>
                <td>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--cy)" }}>{a.id}</div>
                  <div style={{ fontSize: 10, color: "var(--mu)" }}>{ago(a.ts)}</div>
                </td>
                <td style={{ maxWidth: 260 }}>
                  <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.subject}</div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--mu)" }}>{a.recipient}</div>
                </td>
                <td className="mono" style={{ fontSize: 10.5, color: "#9db4c4" }}>{a.sender}</td>
                <td style={{ fontSize: 11 }}>{a.category}</td>
                <td>
                  <div style={{ display: "flex", gap: 3 }}>
                    {["L1", "L2", "L3", "L4"].map((k) => {
                      const v = a.layers[k];
                      const t = v > 70 ? "rd" : v > 45 ? "am" : "gr";
                      return <span key={k} title={k + ": " + v} style={{ width: 16, height: 16, borderRadius: 4, fontSize: 8.5, display: "grid", placeItems: "center", background: TONE[t] + "33", color: TONE[t], border: "1px solid rgba(255,255,255,.07)" }}>{k.charAt(1)}</span>;
                    })}
                  </div>
                </td>
                <td style={{ fontSize: 11 }}>{a.geo.country}<div style={{ fontSize: 9.5, color: "var(--mu)" }}>{a.geo.city} · {a.geo.type}</div></td>
                <td>
                  <div style={{ display: "flex", gap: 7, alignItems: "center" }}>
                    <b className="mono" style={{ color: TONE[sevTone(a.severity)] }}>{a.score}</b>
                    <div style={{ width: 44 }}><Meter v={a.score} tone={sevTone(a.severity)} h={4} /></div>
                  </div>
                </td>
                <td><Badge tone={a.status === "new" ? "rd" : (a.status === "triaged" ? "am" : (a.status === "investigating" ? "cy" : "mu"))}>{a.status}</Badge></td>
                <td onClick={(e) => e.stopPropagation()}>
                  <div style={{ display: "flex", gap: 4 }}>
                    {a.status === "new" ? <button className="btn sm" onClick={() => setStatus(a.id, "triaged")}>Triage</button> : null}
                    {a.status !== "closed" ? <button className="btn sm" onClick={() => setStatus(a.id, "closed")}>Close</button> : null}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {list.length ? null : <Empty t="No alerts match the current filters" />}
      </div>
    </Panel>
  );
}

function AlertDrawer({ a, closing, onClose, toast, setAlerts, goto }) {
  const [tab, setTab] = useState("verdict");
  if (!a) return null;
  const geo = a.geo;
  const hops = [
    { seq: 1, host: "client-host.unknown", ip: a.ip, org: geo.org, asn: geo.asn, country: geo.country, city: geo.city, lat: geo.lat, lon: geo.lon, type: geo.type, note: "Originating client / relay" },
    { seq: 2, host: "smtp-relay.vps-net.io", ip: IPS[(hashStr(a.id) + 3) % IPS.length], org: "VPS-Net Hosting", asn: "AS202425", country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9, type: "hosting", note: "Open relay hop" },
    { seq: 3, host: "mx.google.com", ip: "142.250.180.14", org: "Google LLC", asn: "AS15169", country: "United States", city: "Mountain View", lat: 37.39, lon: -122.08, type: "corporate", note: "Recipient MX (final)" }
  ];
  const explain = [
    { w: 22, t: "Lookalike domain impersonating a trusted brand", d: "Edit-distance + brand-token analysis" },
    { w: 16, t: "SPF validation failed for envelope sender", d: "RFC 7208 alignment check" },
    { w: 15, t: "Anchor text does not match href destination", d: "HTML DOM link inspection" },
    { w: 12, t: "DMARC policy alignment broken", d: "Authentication-Results header" },
    { w: 10, t: "High-risk TLD with known abuse concentration", d: "URLhaus / OpenPhish statistics" },
    { w: 8, t: "Tor exit node in routing chain", d: "Tor project exit list correlation" }
  ];
  const agentDefs = [
    ["Text Agent", a.agents.text, "Content & semantic analysis", "cy"],
    ["URL Agent", a.agents.url, "Link + redirect chain", "rd"],
    ["Metadata Agent", a.agents.metadata, "Headers & behaviour", "am"],
    ["Adversarial Agent", a.agents.adversarial, "Robustness probing", "vi"],
    ["Explanation Simplifier", Math.round((a.agents.text + a.agents.url + a.agents.metadata + a.agents.adversarial) / 4), "Human-readable output", "gr"]
  ];
  const fusionRows = [
    ["Webmail IP leak", "X-Originating-IP present", true, 8.4],
    ["Timezone offset", "Date +0700 vs geo UTC+2", true, 0.55],
    ["Language fingerprint", "Content-Language: zh-CN", true, 4.2],
    ["Infrastructure reuse", "6 prior campaigns on /24", true, 6.5],
    ["Hop chain forgery", "1 malformed Received", false, 4.8],
    ["VPN / exit node", geo.type.toUpperCase(), false, geo.type === "tor" ? 9 : 5.2],
    ["Authentication results", "SPF fail / DMARC fail", false, 3.9],
    ["Webmail provider FP", "self-hosted Postfix", true, 2.2]
  ];
  const prevFix = { city: "Singapore", country: "SG", lat: 1.35, lon: 103.82 };
  const travelKm = haversine(prevFix, geo);
  const travelKmh = Math.round(travelKm / 3.2);

  return (
    <React.Fragment>
      <div className={"ov" + (closing ? " out" : "")} onClick={onClose} />
      <div className={"drawer" + (closing ? " out" : "")}>
        <div className="ph" style={{ padding: "13px 16px" }}>
          <div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <b style={{ fontSize: 13.5 }}>{a.subject}</b>
              <Badge tone={a.verdict === "MALICIOUS" ? "rd" : (a.verdict === "SUSPICIOUS" ? "am" : "gr")} dot>{a.verdict}</Badge>
              <Badge tone={sevTone(a.severity)}>{a.severity}</Badge>
            </div>
            <div className="mono" style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 3 }}>{a.id} · {a.sender} → {a.recipient} · {new Date(a.ts).toUTCString()}</div>
          </div>
          <button className="btn sm" onClick={onClose}><Icon n="x" s={13} /></button>
        </div>
        <div style={{ padding: "10px 16px", borderBottom: "1px solid var(--ln)", display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <div className="tabs">
            {["verdict", "agents", "explain", "hops", "geo", "iocs"].map((t) => (
              <button key={t} className={"tab" + (tab === t ? " on" : "")} onClick={() => setTab(t)}>{t}</button>
            ))}
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <button className="btn sm p" onClick={() => { toast("Case created from " + a.id + " — queued for cases table"); goto("cases"); }}>Create case</button>
            <button className="btn sm" onClick={() => { setAlerts((p) => p.map((x) => (x.id === a.id ? Object.assign({}, x, { status: "investigating" }) : x))); toast("Status → investigating"); }}>Investigate</button>
            <button className="btn sm" onClick={() => { copy(JSON.stringify(a, null, 2)); toast("Alert JSON copied"); }}>Copy JSON</button>
          </div>
        </div>
        <div className="scroll" style={{ padding: 16, flex: 1 }}>
          {tab === "verdict" ? (
            <div className="grid fi">
              <div className="grid" style={{ gridTemplateColumns: "150px 1fr", gap: 14 }}>
                <div style={{ textAlign: "center", background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 12, padding: 14 }}>
                  <div className="mono" style={{ fontSize: 38, fontWeight: 700, color: TONE[sevTone(a.severity)], lineHeight: 1 }}>{a.score}</div>
                  <div style={{ fontSize: 10, color: "var(--mu)", letterSpacing: 1, textTransform: "uppercase" }}>Fused risk</div>
                  <div style={{ marginTop: 8 }}><Meter v={a.score} tone={sevTone(a.severity)} /></div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--mu)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>Multi-layer detection cascade</div>
                  {[["L1 Signature & heuristic", a.layers.L1, "bl"], ["L2 Classical ML (TF-IDF + LR)", a.layers.L2, "cy"], ["L3 Deep learning (DistilBERT)", a.layers.L3, "vi"], ["L4 LLM multi-agent reasoning", a.layers.L4, "rd"]].map((r) => (
                    <div key={r[0]} style={{ marginBottom: 9 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }}><span>{r[0]}</span><b className="mono" style={{ color: TONE[r[2]] }}>{r[1]}</b></div>
                      <div style={{ marginTop: 4 }}><Meter v={r[1]} tone={r[2]} /></div>
                    </div>
                  ))}
                </div>
              </div>
              <Panel title="Plain-language verdict" sub="Explanation Simplifier agent output">
                <p style={{ margin: 0, lineHeight: 1.75, fontSize: 12.5, color: "#cfe2ee" }}>
                  This message is <b style={{ color: TONE[sevTone(a.severity)] }}>{a.verdict.toLowerCase()}</b>. It pretends to be from a trusted brand but was sent
                  from an unauthorized server ({a.sender}) that failed SPF and DMARC checks. The visible link text does not match where it actually goes, and the
                  message was routed through a <b>{geo.type}</b> node in <b>{geo.city}, {geo.country}</b>. Recommended action: quarantine the message, block the
                  sending domain, and reset credentials if the recipient clicked any link.
                </p>
              </Panel>
              <div className="kv" style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 10, padding: 12 }}>
                <div>Category</div><div>{a.category}</div>
                <div>Message-ID</div><div className="mono" style={{ fontSize: 11 }}>{a.id.toLowerCase()}.{hashStr(a.id).toString(16)}@northwind-logistics.com</div>
                <div>Tenant</div><div>{a.tenant}</div>
                <div>Model version</div><div className="mono" style={{ fontSize: 11 }}>distilbert-phish-v4.2 · xgb-2025.05 · agents-ppo-v3</div>
                <div>Ingest → verdict</div><div className="mono" style={{ fontSize: 11 }}>{a.layers.L4 > 80 ? 186 : 128} ms</div>
              </div>
            </div>
          ) : null}

          {tab === "agents" ? (
            <div className="grid fi">
              <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))" }}>
                {agentDefs.map((d) => (
                  <div key={d[0]} style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 10, padding: 12 }}>
                    <div style={{ fontSize: 11.5, fontWeight: 600 }}>{d[0]}</div>
                    <div style={{ fontSize: 10, color: "var(--mu)", minHeight: 26, marginTop: 2 }}>{d[2]}</div>
                    <div className="mono" style={{ fontSize: 24, color: TONE[d[3]], margin: "4px 0 6px" }}>{Math.round(d[1])}</div>
                    <Meter v={d[1]} tone={d[3]} />
                  </div>
                ))}
              </div>
              <Panel title="PPO decision-fusion weights" sub="Reinforcement-learned agent weighting from historical performance">
                {[["text", 0.24], ["url", 0.31], ["metadata", 0.27], ["adversarial", 0.18]].map((w) => (
                  <div key={w[0]} style={{ marginBottom: 9 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }}>
                      <span className="mono">{w[0]}</span>
                      <span className="mono" style={{ color: "var(--cy)" }}>{(w[1] * 100).toFixed(0)}% · contribution {(a.agents[w[0]] * w[1]).toFixed(1)}</span>
                    </div>
                    <div style={{ marginTop: 4 }}><Meter v={w[1] * 300} tone="cy" /></div>
                  </div>
                ))}
                <div className="chip" style={{ marginTop: 6 }}>
                  fused = sum(agent x weight) = {Object.keys(a.agents).reduce((s, k) => s + a.agents[k] * ({ text: 0.24, url: 0.31, metadata: 0.27, adversarial: 0.18 }[k] || 0), 0).toFixed(1)}
                </div>
              </Panel>
              <Panel title="Adversarial training loop" sub="variants generated by the Adversarial Agent for this sample">
                {["Homoglyph substitution: micros0ft → microѕoft (Cyrillic ѕ)", "Zero-width joiner inserted into anchor text", "Unicode bidi override in display name", "Base64-encoded HTML body with deferred CTA", "Redirect chain extended by 2 hops"].map((v, i) => (
                  <div className="mrow" key={i}>
                    <span className="dot" style={{ background: "var(--vi)" }} />
                    <div style={{ fontSize: 11.5, flex: 1 }}>{v}</div>
                    <Badge tone={i % 2 ? "gr" : "rd"}>{i % 2 ? "detected" : "blocked"}</Badge>
                  </div>
                ))}
              </Panel>
            </div>
          ) : null}

          {tab === "explain" ? (
            <div className="grid fi">
              <Panel title="SHAP feature attribution" sub="localised explanation (BDI-SHAP-X + LIME cross-check)">
                {explain.map((e, i) => (
                  <div key={i} style={{ marginBottom: 10 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                      <div style={{ fontSize: 11.5 }}>{e.t}<div style={{ fontSize: 10, color: "var(--mu)" }}>{e.d}</div></div>
                      <b className="mono" style={{ color: "var(--rd)", fontSize: 12 }}>+{e.w}</b>
                    </div>
                    <div style={{ marginTop: 5 }}><Meter v={e.w * 4} tone="rd" h={5} /></div>
                  </div>
                ))}
              </Panel>
              <Panel title="Transformer attention (BERTViz)" sub="token-level attention on the highest-scoring head">
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {[["URGENT", 96], ["final", 82], ["notice", 88], ["suspended", 91], ["wire", 94], ["transfer", 79], ["beneficiary", 71], ["SWIFT", 66], ["24", 58], ["hours", 61], ["verify", 74], ["account", 49], ["invoice", 55], ["click", 44]].map((t) => (
                    <span key={t[0]} className="mono" style={{ padding: "4px 8px", borderRadius: 6, fontSize: 11, background: "rgba(251,113,133," + (t[1] / 320) + ")", border: "1px solid rgba(251,113,133," + (t[1] / 180) + ")", color: "#ffd9e0" }}>
                      {t[0]} <b style={{ color: "#fff", opacity: 0.8 }}>{t[1]}</b>
                    </span>
                  ))}
                </div>
              </Panel>
            </div>
          ) : null}

          {tab === "hops" ? (
            <div className="grid fi">
              <Panel title="Hop chain visualization" sub="every relay, ASN and location in the routing path">
                {hops.map((h, i) => (
                  <div className="hop" key={i}>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                      <span className="dot" style={{ background: (h.type === "tor" || h.type === "vpn") ? "var(--rd)" : (h.type === "hosting" ? "var(--am)" : "var(--gr)") }} />
                      {i < hops.length - 1 ? <div style={{ width: 1, flex: 1, background: "var(--ln2)", minHeight: 12 }} /> : null}
                    </div>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 600 }}>Hop {h.seq} · {h.host}</div>
                      <div className="mono" style={{ fontSize: 10.5, color: "#9db4c4", marginTop: 2 }}>{h.ip} · {h.asn} · {h.org}</div>
                      <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 2 }}>{h.city}, {h.country} — {h.note}</div>
                    </div>
                    <Badge tone={(h.type === "tor" || h.type === "vpn") ? "rd" : (h.type === "hosting" ? "am" : "gr")}>{h.type}</Badge>
                  </div>
                ))}
              </Panel>
              <WorldMap
                points={hops.map((h, i) => ({ id: "h" + i, lon: h.lon, lat: h.lat, label: "Hop " + h.seq + " " + h.city, tone: h.type === "corporate" ? "gr" : "rd", pulse: i === 0 }))}
                arcs={hops.slice(0, hops.length - 1).map((h, i) => ({ from: h, to: hops[i + 1], tone: "rd", w: 1.6 }))}
                height={230}
              />
            </div>
          ) : null}

          {tab === "geo" ? (
            <div className="grid fi">
              <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <Panel title="Attributed origin" sub="HUNTERTRACE multi-signal fusion">
                  <div className="kv">
                    <div>Origin IP</div><div className="mono">{a.ip}</div>
                    <div>Country</div><div>{geo.country} ({geo.cc})</div>
                    <div>Region / city</div><div>{geo.city}</div>
                    <div>Coordinates</div><div className="mono" style={{ fontSize: 11 }}>{geo.lat}, {geo.lon}</div>
                    <div>ASN</div><div className="mono" style={{ fontSize: 11 }}>{geo.asn}</div>
                    <div>Organisation</div><div>{geo.org}</div>
                    <div>Node class</div><div><Badge tone={(geo.type === "tor" || geo.type === "vpn") ? "rd" : (geo.type === "hosting" ? "am" : "gr")}>{geo.type}</Badge></div>
                    <div>ACI confidence</div><div><b style={{ color: "var(--cy)" }}>{clamp(38 + (a.score % 47), 20, 94)}%</b> (Bayesian posterior)</div>
                  </div>
                </Panel>
                <Panel title="Impossible travel" sub="velocity check against sender history">
                  <div className="kv">
                    <div>Previous fix</div><div>{prevFix.city}, {prevFix.country} · 3.2 h ago</div>
                    <div>Current fix</div><div>{geo.city}, {geo.country}</div>
                    <div>Distance</div><div className="mono">{fmt(travelKm)} km</div>
                    <div>Implied speed</div><div className="mono" style={{ color: travelKmh > 900 ? "var(--rd)" : "var(--gr)" }}>{fmt(travelKmh)} km/h</div>
                    <div>Threshold</div><div className="mono">900 km/h</div>
                    <div>Verdict</div><div><Badge tone={travelKmh > 900 ? "rd" : "gr"}>{travelKmh > 900 ? "physically impossible" : "plausible"}</Badge></div>
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <WorldMap
                      points={[{ id: "p", lon: prevFix.lon, lat: prevFix.lat, label: prevFix.city, tone: "cy" }, { id: "c", lon: geo.lon, lat: geo.lat, label: geo.city, tone: "rd", pulse: true }]}
                      arcs={[{ from: prevFix, to: geo, tone: "rd", w: 1.6 }]}
                      height={150}
                    />
                  </div>
                </Panel>
              </div>
              <Panel title="Bayesian signal fusion" sub="8+ orthogonal signals, VPN-resistant where possible" bodyStyle={{ padding: 0 }}>
                <table>
                  <thead><tr><Th>Signal</Th><Th>Evidence</Th><Th>VPN-resistant</Th><Th>Likelihood ratio</Th><Th>Contribution</Th></tr></thead>
                  <tbody>
                    {fusionRows.map((r, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: 11.5 }}>{r[0]}</td>
                        <td className="mono" style={{ fontSize: 10.5, color: "#9db4c4" }}>{r[1]}</td>
                        <td>{r[2] ? <Badge tone="gr">yes</Badge> : <Badge tone="mu">partial</Badge>}</td>
                        <td className="mono">{r[3].toFixed(1)}×</td>
                        <td style={{ width: 130 }}><Meter v={clamp(r[3] * 10, 0, 100)} tone="cy" h={5} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div style={{ padding: "10px 14px", fontSize: 11, color: "var(--mu)" }}>Country-level accuracy 52.8% · region-level 56.6% (vs ~31% for single-signal IP geolocation).</div>
              </Panel>
            </div>
          ) : null}

          {tab === "iocs" ? (
            <Panel className="fi" title="Extracted indicators" sub="IOC extraction + enrichment pipeline" bodyStyle={{ padding: 0 }}>
              <table>
                <thead><tr><Th>Type</Th><Th>Value</Th><Th>Sources</Th><Th>Confidence</Th><Th></Th></tr></thead>
                <tbody>
                  {a.iocs.concat([{ type: "sha256", value: "5d41402abc4b2a76b9719d911017c592781003a4a0d0b7f4c2e1a9d6b8f03c11", src: "VirusTotal 34/72", conf: 81 }]).map((i, k) => (
                    <tr key={k}>
                      <td><Badge tone="vi">{i.type}</Badge></td>
                      <td className="mono" style={{ fontSize: 10.5, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis" }}>{i.value}</td>
                      <td style={{ fontSize: 11, color: "var(--mu)" }}>{i.src || "Internal detection"}</td>
                      <td className="mono">{i.conf || 70}</td>
                      <td><button className="btn sm" onClick={() => { copy(i.value); toast("Copied " + i.value.slice(0, 24)); }}>Copy</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          ) : null}
        </div>
      </div>
    </React.Fragment>
  );
}

const PIPE_STAGES = [
  ["L1", "Signature & heuristic", "SPF/DKIM/DMARC · blacklists · rule engine"],
  ["L2", "Classical ML", "TF-IDF + Logistic Regression · Random Forest · XGBoost"],
  ["L3", "Deep learning", "DistilBERT · BiLSTM · BERT+CNN+GRU attention"],
  ["L4", "LLM multi-agent", "Text · URL · Metadata · Adversarial · Simplifier"],
  ["GEO", "Geolocation fusion", "10-stage HUNTERTRACE pipeline"],
  ["IOC", "Forensic extraction", "IPs · domains · URLs · hashes · attachments"],
  ["ACT", "Response & archive", "Quarantine · recall · immutable evidence"]
];

function Analyzer({ sb, toast, setAlerts }) {
  const [raw, setRaw] = useState(SAMPLE_EML);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState(-1);
  const [res, setRes] = useState(null);
  const parsed = useMemo(() => parseEmail(raw), [raw]);

  const run = () => {
    if (!raw.trim()) { toast("Paste a raw email (.eml) first"); return; }
    setRunning(true); setRes(null); setStage(0);
    let i = 0;
    const tick = () => {
      i = i + 1;
      if (i < PIPE_STAGES.length) { setStage(i); setTimeout(tick, 320 + rnd(i * 7) * 220); return; }
      const p = parseEmail(raw);
      const r = analyzeEmail(p);
      const g = attributeGeo(p);
      setRes({ p: p, r: r, g: g });
      setRunning(false);
      setStage(-1);
    };
    setTimeout(tick, 340);
  };

  const save = async () => {
    if (!res) { toast("Run the analysis first"); return; }
    const h = await sha256(res.p.raw);
    if (sb.status === "connected" && sb.client) {
      try {
        const ins = await sb.client.from("emails").insert({
          message_id: res.p.messageId, ts: new Date().toISOString(), sender: res.p.fromAddr,
          sender_domain: res.p.senderDomain, recipient: res.p.to, subject: res.p.subject,
          size_bytes: res.p.raw.length, sha256: h, body_text: res.p.bodyText.slice(0, 4000),
          headers: res.p.headers, attachments: res.p.attachments
        }).select();
        if (ins.error) throw ins.error;
        const row = ins.data && ins.data[0] ? ins.data[0] : null;
        if (row) {
          await sb.client.from("detections").insert({
            email_id: row.id, score: res.r.score, verdict: res.r.verdict, severity: res.r.severity,
            layer1: res.r.layers.L1, layer2: res.r.layers.L2, layer3: res.r.layers.L3, layer4: res.r.layers.L4,
            agents: res.r.agents, ppo_weights: res.r.ppo, explain: res.r.findings.slice(0, 12),
            model_version: "distilbert-phish-v4.2", latency_ms: 142
          });
        }
        toast("Saved to Supabase: emails + detections");
      } catch (e) {
        toast("Supabase write failed: " + (e.message || e));
      }
      return;
    }
    const p = res.p;
    const ext = p.hops.filter((x) => !isPrivate(x.ip));
    const g = geoFor(ext.length ? ext[0].ip : IPS[2]) || geoFor(IPS[2]);
    setAlerts((prev) => {
      const na = {
        id: "ALT-S" + String(91600 + prev.length), ts: new Date().toISOString(),
        subject: p.subject || "(no subject)", sender: p.fromAddr, recipient: p.to,
        category: "Analyst submission", score: res.r.score, severity: res.r.severity, verdict: res.r.verdict,
        layers: res.r.layers, agents: res.r.agents, ip: res.g.originIp || g.ip, geo: g,
        status: "new", tenant: "northwind", iocs: [{ type: "domain", value: p.senderDomain }], fresh: true
      };
      return [na].concat(prev);
    });
    toast("Demo mode — added to local alert bus (connect Supabase to persist)");
  };

  return (
    <div className="grid fu">
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel title="Raw message input" sub=".eml / RFC 2822 — headers + body"
          right={
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn sm" onClick={() => setRaw(SAMPLE_EML)}>Load sample</button>
              <button className="btn sm" onClick={() => setRaw("")}>Clear</button>
              <button className="btn sm" onClick={() => { copy(raw); toast("Raw message copied"); }}><Icon n="copy" s={12} /></button>
            </div>
          }>
          <textarea className="inp" rows={19} value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false} placeholder="Paste raw email source here…" />
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 9 }}>
            <span className="chip">{parsed.headerList.length} headers</span>
            <span className="chip">{parsed.received.length} Received</span>
            <span className="chip">{parsed.urls.length} URLs</span>
            <span className="chip">{parsed.hashes.length} hashes</span>
            <span className="chip">{parsed.attachments.length} attachments</span>
            <span className="chip">{parsed.bodyText.split(/\s+/).filter(Boolean).length} words</span>
          </div>
        </Panel>

        <Panel title="Analysis pipeline" sub="Multi-layered detection cascade"
          right={
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn p" onClick={run} disabled={running}>
                <Icon n={running ? "refresh" : "play"} s={13} c="#eafeff" />{running ? "Analyzing…" : "Run deep analysis"}
              </button>
              <button className="btn" onClick={save} disabled={!res}><Icon n="db" s={13} />Save</button>
            </div>
          }>
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {PIPE_STAGES.map((s, i) => {
              const done = !!res || (running && i < stage);
              const active = running && i === stage;
              let op = 0.55;
              if (res) op = 1;
              else if (running) op = i <= stage ? 1 : 0.4;
              return (
                <div key={s[0]} style={{
                  opacity: op, transition: "opacity .3s ease, transform .3s ease", transform: active ? "translateX(3px)" : "none",
                  display: "flex", gap: 10, alignItems: "center", padding: "8px 10px", borderRadius: 9,
                  border: "1px solid " + (active ? "rgba(34,211,238,.5)" : done ? "rgba(52,211,153,.28)" : "var(--ln)"),
                  background: active ? "rgba(34,211,238,.08)" : done ? "rgba(52,211,153,.05)" : "#0a121d"
                }}>
                  <span className="mono" style={{ fontSize: 9.5, fontWeight: 700, color: active ? "var(--cy)" : done ? "var(--gr)" : "var(--mu)", width: 30 }}>{s[0]}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11.8, fontWeight: 550 }}>{s[1]}</div>
                    <div style={{ fontSize: 10, color: "var(--mu)" }}>{s[2]}</div>
                  </div>
                  {active
                    ? <span className="spin" style={{ color: "var(--cy)" }}><Icon n="refresh" s={14} /></span>
                    : done
                      ? <span style={{ color: "var(--gr)", display: "inline-flex" }}><Icon n="check" s={14} /></span>
                      : <span className="mono" style={{ fontSize: 10, color: "#3d5364" }}>idle</span>}
                </div>
              );
            })}
          </div>
          {res ? (
            <div className="fu" style={{ marginTop: 12, background: "#0a121d", border: "1px solid " + TONE[sevTone(res.r.severity)] + "44", borderRadius: 11, padding: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ textAlign: "center" }}>
                  <div className="mono" style={{ fontSize: 40, fontWeight: 700, color: TONE[sevTone(res.r.severity)], lineHeight: 1 }}>{res.r.score}</div>
                  <div style={{ fontSize: 9.5, letterSpacing: 1.2, color: "var(--mu)", textTransform: "uppercase" }}>risk</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", gap: 7, marginBottom: 7, flexWrap: "wrap" }}>
                    <Badge tone={res.r.verdict === "MALICIOUS" ? "rd" : (res.r.verdict === "SUSPICIOUS" ? "am" : "gr")} dot>{res.r.verdict}</Badge>
                    <Badge tone={sevTone(res.r.severity)}>{res.r.severity}</Badge>
                    <Badge tone="cy">{res.r.findings.length} findings</Badge>
                  </div>
                  <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 8 }}>
                    {Object.keys(res.r.layers).map((k) => (
                      <div key={k}>
                        <div className="mono" style={{ fontSize: 9.5, color: "var(--mu)" }}>{k}</div>
                        <Meter v={res.r.layers[k]} tone={res.r.layers[k] > 70 ? "rd" : (res.r.layers[k] > 45 ? "am" : "gr")} h={5} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </Panel>
      </div>

      {res ? <AnalyzerResult res={res} toast={toast} /> : null}

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel title="Parsed headers" sub={parsed.headerList.length + " RFC 2822 header fields"} bodyStyle={{ padding: 0 }}>
          <div className="scroll" style={{ maxHeight: 300 }}>
            <table>
              <tbody>
                {parsed.headerList.map((h, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: "var(--cy)", fontSize: 10.5, width: 190, whiteSpace: "nowrap" }}>{h.k}</td>
                    <td className="mono" style={{ fontSize: 10.5, color: "#b9cede", wordBreak: "break-all" }}>{h.v.slice(0, 260)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {parsed.headerList.length ? null : <Empty t="No headers detected" />}
          </div>
        </Panel>
        <Panel title="Authentication & routing" sub="SPF / DKIM / DMARC alignment and Received chain">
          <div className="grid" style={{ gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 12 }}>
            {["spf", "dkim", "dmarc"].map((k) => {
              const v = parsed.auth[k];
              const ok = v === "pass";
              return (
                <div key={k} style={{ background: "#0a121d", border: "1px solid " + (ok ? "rgba(52,211,153,.35)" : "rgba(251,113,133,.35)"), borderRadius: 9, padding: 10, textAlign: "center" }}>
                  <div style={{ fontSize: 10, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase" }}>{k}</div>
                  <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: ok ? "var(--gr)" : (v === "unknown" ? "var(--mu)" : "var(--rd)"), marginTop: 3 }}>{v.toUpperCase()}</div>
                </div>
              );
            })}
          </div>
          <div style={{ fontSize: 10, color: "var(--mu)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Received chain ({parsed.received.length})</div>
          <div className="scroll" style={{ maxHeight: 190 }}>
            {parsed.received.map((r, i) => (
              <div className="hop" key={i}>
                <span className="dot" style={{ background: isPrivate(r.ip) ? "var(--mu)" : (r.ip ? "var(--am)" : "#3d5364"), marginTop: 5 }} />
                <div>
                  <div style={{ fontSize: 11.5 }}>Hop {i + 1} · <span className="mono">{r.from}</span> {r.by ? <span style={{ color: "var(--mu)" }}>→ by {r.by}</span> : null}</div>
                  <div className="mono" style={{ fontSize: 10, color: "#9db4c4", marginTop: 2 }}>{r.ip || "no IP"} {r.host ? "· " + r.host : ""}</div>
                  <div style={{ fontSize: 10, color: "var(--mu)", marginTop: 2 }}>{r.date || "no timestamp"}</div>
                </div>
                <Badge tone={isPrivate(r.ip) ? "mu" : "am"}>{isPrivate(r.ip) ? "internal" : (r.ip ? "external" : "?")}</Badge>
              </div>
            ))}
            {parsed.received.length ? null : <Empty t="No Received headers found" />}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function AnalyzerResult({ res, toast }) {
  const p = res.p, r = res.r, g = res.g;
  const extHops = p.hops.filter((h) => !isPrivate(h.ip));
  const mapPts = extHops.map((h, i) => {
    const gg = geoFor(h.ip);
    return { id: "mh" + i, lon: gg.lon, lat: gg.lat, label: "Hop " + (i + 1) + " · " + gg.city, tone: gg.type === "corporate" ? "gr" : (gg.type === "residential" ? "cy" : "rd"), pulse: i === extHops.length - 1 };
  });
  if (g.g) mapPts.unshift({ id: "org", lon: g.g.lon, lat: g.g.lat, label: "Attributed origin · " + g.g.city, tone: "rd", pulse: true });
  const arcs = mapPts.length > 1 ? mapPts.slice(0, mapPts.length - 1).map((a, i) => ({ from: a, to: mapPts[i + 1], tone: "rd", w: 1.5 })) : [];

  const iocPairs = [];
  p.hosts.forEach((v) => iocPairs.push(["domain", v]));
  p.urls.forEach((v) => iocPairs.push(["url", v]));
  p.ips.filter((i) => !isPrivate(i)).forEach((v) => iocPairs.push(["ip", v]));
  p.hashes.forEach((v) => iocPairs.push(["sha256", v]));
  p.emails.forEach((v) => iocPairs.push(["email", v]));

  let plain = "Nothing looks wrong with this message. Authentication and content checks passed.";
  if (r.verdict !== "BENIGN") {
    const top = r.findings.slice(0, 2).map((f) => f.label).join(" and ");
    const where = g.g ? " It was sent from infrastructure in " + g.g.city + ", " + g.g.country + " (" + g.g.type + " node)." : "";
    plain = "This email is " + r.verdict.toLowerCase() + " (" + r.score + "/100). Top reasons: " + (top || "none") + "." + where + " Quarantine the message and block the sender domain.";
  }

  return (
    <div className="grid fu">
      <div className="grid" style={{ gridTemplateColumns: "1.1fr 1fr 1fr", gap: 12 }}>
        <Panel title="Findings (SHAP-ranked)" sub={r.findings.length + " weighted indicators"} bodyStyle={{ padding: "6px 14px 12px" }}>
          <div className="scroll" style={{ maxHeight: 300 }}>
            {r.findings.map((f) => (
              <div key={f.id} style={{ padding: "8px 0", borderBottom: "1px solid rgba(120,180,220,.07)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <div><span className="mono" style={{ fontSize: 9, color: "var(--mu)", marginRight: 6 }}>{f.layer}</span><b style={{ fontSize: 11.8 }}>{f.label}</b></div>
                  <span className="mono" style={{ color: TONE[f.tone], fontSize: 11.5, fontWeight: 700 }}>{f.weight > 0 ? "+" : ""}{f.weight}</span>
                </div>
                <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 2 }}>{f.detail}</div>
              </div>
            ))}
            {r.findings.length ? null : <Empty t="No suspicious indicators — message appears benign" />}
          </div>
        </Panel>

        <Panel title="Multi-agent verdicts" sub="5 cooperative agents, PPO-weighted fusion">
          {Object.keys(r.agents).map((k) => {
            const v = r.agents[k];
            const t = v > 70 ? "rd" : (v > 45 ? "am" : "gr");
            return (
              <div key={k} style={{ marginBottom: 9 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }}>
                  <span>{k} agent</span>
                  <b className="mono" style={{ color: TONE[t] }}>{Math.round(v)}</b>
                </div>
                <div style={{ marginTop: 4 }}><Meter v={v} tone={t} /></div>
                <div className="mono" style={{ fontSize: 9.5, color: "var(--mu)", marginTop: 3 }}>PPO weight {(r.ppo[k] * 100).toFixed(0)}% → contribution {(v * r.ppo[k]).toFixed(1)}</div>
              </div>
            );
          })}
          <div style={{ marginTop: 10, padding: 10, background: "#0a121d", borderRadius: 9, border: "1px solid var(--ln)" }}>
            <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase" }}>Explanation Simplifier</div>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, lineHeight: 1.65, color: "#cfe2ee" }}>{plain}</p>
          </div>
        </Panel>

        <Panel title="Geolocation attribution" sub={g.g ? "HUNTERTRACE Bayesian fusion" : "No routable origin found"}>
          {g.g ? (
            <div>
              <div className="kv">
                <div>Origin IP</div><div className="mono">{g.originIp}</div>
                <div>Location</div><div>{g.g.city}, {g.g.country} ({g.g.cc})</div>
                <div>Coords</div><div className="mono" style={{ fontSize: 11 }}>{g.g.lat}, {g.g.lon}</div>
                <div>ASN / org</div><div style={{ fontSize: 11 }}>{g.g.asn} · {g.g.org}</div>
                <div>Node class</div><div><Badge tone={(g.g.type === "tor" || g.g.type === "vpn") ? "rd" : (g.g.type === "hosting" ? "am" : "gr")}>{g.g.type}</Badge></div>
                <div>ACI confidence</div><div><b style={{ color: "var(--cy)" }}>{g.confidence}%</b></div>
                <div>Country acc.</div><div className="mono" style={{ fontSize: 11 }}>52.8% fleet baseline</div>
              </div>
              {g.travel ? (
                <div style={{ marginTop: 10, padding: 10, borderRadius: 9, border: "1px solid " + (g.travel.impossible ? "rgba(251,113,133,.4)" : "rgba(52,211,153,.35)"), background: g.travel.impossible ? "rgba(251,113,133,.08)" : "rgba(52,211,153,.07)" }}>
                  <div style={{ display: "flex", gap: 7, alignItems: "center", marginBottom: 5 }}>
                    <Icon n="warn" s={13} c={g.travel.impossible ? "#fb7185" : "#34d399"} />
                    <b style={{ fontSize: 11.5 }}>Impossible travel {g.travel.impossible ? "DETECTED" : "not detected"}</b>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "#b9cede" }}>
                    {g.travel.prev.city} → {g.g.city} · {fmt(g.travel.distanceKm)} km in {g.travel.hours} h = {fmt(g.travel.kmh)} km/h
                  </div>
                </div>
              ) : null}
            </div>
          ) : <Empty t="No external IP in routing chain" />}
        </Panel>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.35fr 1fr", gap: 12 }}>
        <Panel title="Routing map & hop chain" sub={mapPts.length + " geo-resolved hops"} right={<Badge tone="cy">{g.g ? "origin: " + g.g.country : "no origin"}</Badge>}>
          <WorldMap points={mapPts} arcs={arcs} height={268} />
          <div style={{ marginTop: 10 }}>
            {p.received.map((h, i) => {
              const gg = h.ip ? geoFor(h.ip) : null;
              const anon = gg && (gg.type === "tor" || gg.type === "vpn");
              return (
                <div className="hop" key={i}>
                  <span className="dot" style={{ background: !h.ip ? "#3d5364" : anon ? "var(--rd)" : (gg && gg.type === "hosting" ? "var(--am)" : (isPrivate(h.ip) ? "var(--mu)" : "var(--gr)")), marginTop: 5 }} />
                  <div>
                    <div style={{ fontSize: 11.5 }}>Hop {i + 1} · <span className="mono">{h.from}</span></div>
                    <div className="mono" style={{ fontSize: 10, color: "#9db4c4", marginTop: 2 }}>{h.ip || "—"} {gg && !isPrivate(h.ip) ? "· " + gg.asn + " · " + gg.org : ""}</div>
                    <div style={{ fontSize: 10, color: "var(--mu)", marginTop: 2 }}>{gg && !isPrivate(h.ip) ? gg.city + ", " + gg.country : "internal / unresolvable"} {h.date ? "· " + h.date : ""}</div>
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    {gg && gg.type === "tor" ? <Badge tone="rd">tor exit</Badge> : null}
                    {gg && gg.type === "vpn" ? <Badge tone="rd">vpn</Badge> : null}
                    {isPrivate(h.ip) ? <Badge tone="mu">private</Badge> : null}
                    {!h.by ? <Badge tone="am">forged?</Badge> : null}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <div className="grid">
          <Panel title="Extracted IOCs" sub="auto-enriched across 7 feeds" bodyStyle={{ padding: "4px 14px 12px" }}>
            <div className="scroll" style={{ maxHeight: 168 }}>
              {iocPairs.map((pair, i) => (
                <div className="mrow" key={i}>
                  <Badge tone="vi">{pair[0]}</Badge>
                  <div className="mono" style={{ flex: 1, fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{pair[1]}</div>
                  <button className="btn sm" onClick={() => { copy(pair[1]); toast("Copied IOC"); }}><Icon n="copy" s={11} /></button>
                </div>
              ))}
              {iocPairs.length ? null : <Empty t="No IOCs extracted" />}
            </div>
          </Panel>

          <Panel title="Link & anchor integrity" sub="visible text vs. real destination">
            {p.anchors.length ? p.anchors.map((a, i) => {
              let hrefHost = a.href;
              try { hrefHost = new URL(a.href).hostname; } catch (e) {}
              const mismatch = /[\w-]+\.[a-z]{2,}/i.test(a.text) && a.text.indexOf(hrefHost) < 0;
              return (
                <div key={i} style={{ marginBottom: 8, padding: 9, background: "#0a121d", borderRadius: 8, border: "1px solid " + (mismatch ? "rgba(251,113,133,.35)" : "var(--ln)") }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span className="mono" style={{ fontSize: 10.5, color: "#9db4c4", overflow: "hidden", textOverflow: "ellipsis" }}>text: {a.text}</span>
                    <Badge tone={mismatch ? "rd" : "gr"}>{mismatch ? "mismatch" : "ok"}</Badge>
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: mismatch ? "#ffc2cd" : "var(--mu)", marginTop: 3, overflow: "hidden", textOverflow: "ellipsis" }}>href: {hrefHost}</div>
                </div>
              );
            }) : <Empty t="No HTML anchors in body" />}
            {p.attachments.length ? (
              <div style={{ marginTop: 8 }}>
                <div style={{ fontSize: 10, color: "var(--mu)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Attachments</div>
                {p.attachments.map((a, i) => <span className="chip" key={i}>{a}</span>)}
              </div>
            ) : null}
          </Panel>

          <Panel title="Signal fusion table" sub="likelihood ratios → posterior confidence" bodyStyle={{ padding: "4px 14px 12px" }}>
            {g.signals.length ? g.signals.map((s, i) => (
              <div key={i} style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                  <span>{s.name} {s.vpnResistant ? <span style={{ color: "var(--gr)", fontSize: 9 }}>VPN✓</span> : null}</span>
                  <b className="mono" style={{ color: s.lr > 3 ? "var(--rd)" : (s.lr < 1 ? "var(--gr)" : "var(--am)") }}>{s.lr.toFixed(1)}×</b>
                </div>
                <div className="mono" style={{ fontSize: 9.8, color: "var(--mu)", marginTop: 1 }}>{s.src} — {s.note}</div>
                <div style={{ marginTop: 3 }}><Meter v={clamp(s.lr * 10, 3, 100)} tone={s.lr > 3 ? "rd" : (s.lr < 1 ? "gr" : "am")} h={4} /></div>
              </div>
            )) : <Empty t="No routable origin to fuse" />}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function GeoPage({ alerts }) {
  const [sel, setSel] = useState(null);
  const [layer, setLayer] = useState("threats");
  const points = useMemo(() => {
    if (layer === "hops") {
      const out = [];
      alerts.slice(0, 6).forEach((a) => {
        const g1 = a.geo;
        const g2 = geoFor(IPS[(hashStr(a.id) + 2) % IPS.length]);
        out.push({ id: a.id + "-0", lon: g1.lon, lat: g1.lat, label: g1.city + " (" + g1.type + ")", tone: "rd", pulse: false, alertId: a.id });
        out.push({ id: a.id + "-1", lon: g2.lon, lat: g2.lat, label: g2.city + " (" + g2.type + ")", tone: "am", pulse: false, alertId: a.id });
      });
      return out;
    }
    return alerts.map((a) => ({
      id: a.id, lon: a.geo.lon, lat: a.geo.lat,
      label: a.geo.city + ", " + a.geo.country + " · " + a.score,
      tone: a.severity === "critical" ? "rd" : (a.severity === "high" ? "am" : "cy"),
      pulse: a.severity === "critical", alertId: a.id
    }));
  }, [alerts, layer]);

  const byCountry = Object.keys(alerts.reduce((m, a) => { m[a.geo.country] = (m[a.geo.country] || 0) + 1; return m; }, {}))
    .map((c) => [c, alerts.reduce((m, a) => m + (a.geo.country === c ? 1 : 0), 0)])
    .sort((a, b) => b[1] - a[1]);

  const selPoint = sel ? points.filter((x) => x.id === sel)[0] : null;
  const selAlert = selPoint && selPoint.alertId ? alerts.filter((x) => x.id === selPoint.alertId)[0] : null;
  const selGeo = geoFor(selAlert ? selAlert.ip : alerts[0].ip);

  return (
    <div className="grid fu">
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))" }}>
        <Stat label="Attributed origins" value={alerts.map((a) => a.ip).filter((v, i, arr) => arr.indexOf(v) === i).length} sub="unique IPs in window" tone="cy" icon="globe" />
        <Stat label="Countries" value={byCountry.length} sub="multi-signal fusion" tone="vi" icon="flag" delay={40} />
        <Stat label="VPN / Tor exits" value={alerts.filter((a) => a.geo.type === "vpn" || a.geo.type === "tor").length} sub="anonymised infrastructure" tone="rd" icon="lock" delay={80} />
        <Stat label="Country accuracy" value="52.8%" sub="region 56.6% vs 31% single-signal" tone="gr" icon="target" delay={120} />
        <Stat label="Impossible travel" value={alerts.filter((a) => a.severity === "critical").length} sub="velocity anomalies flagged" tone="am" icon="warn" delay={160} />
      </div>

      <Panel title="Geolocation intelligence map" sub="sender origins, relay hops and adversary infrastructure"
        right={
          <div className="tabs">
            {["threats", "hops"].map((l) => (
              <button key={l} className={"tab" + (layer === l ? " on" : "")} onClick={() => { setLayer(l); setSel(null); }}>{l}</button>
            ))}
          </div>
        }>
        <WorldMap points={points} selected={sel} onSelect={(pt) => setSel(pt.id)}
          arcs={layer === "hops" ? points.slice(0, points.length - 1).map((pt, i) => ({ from: pt, to: points[i + 1], tone: "rd", w: 1.4 })) : []}
          height={400} />
        <div style={{ display: "flex", gap: 14, marginTop: 10, flexWrap: "wrap", fontSize: 10.5, color: "var(--mu)" }}>
          {[["rd", "critical / anonymised"], ["am", "high / hosting"], ["cy", "medium / commercial"], ["gr", "trusted corporate"]].map((x) => (
            <span key={x[0]} style={{ display: "flex", alignItems: "center", gap: 5 }}><span className="dot" style={{ background: TONE[x[0]] }} />{x[1]}</span>
          ))}
        </div>
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <Panel title="Origin inspector" sub={selPoint ? selPoint.label : "select a marker on the map"}>
          {selPoint ? (
            <div className="fi">
              <div className="kv">
                <div>IP</div><div className="mono">{selGeo.ip}</div>
                <div>Country</div><div>{selGeo.country} ({selGeo.cc})</div>
                <div>City</div><div>{selGeo.city}</div>
                <div>Coordinates</div><div className="mono" style={{ fontSize: 11 }}>{selGeo.lat}, {selGeo.lon}</div>
                <div>ASN</div><div className="mono" style={{ fontSize: 11 }}>{selGeo.asn}</div>
                <div>Organisation</div><div style={{ fontSize: 11 }}>{selGeo.org}</div>
                <div>Classification</div><div><Badge tone={(selGeo.type === "tor" || selGeo.type === "vpn") ? "rd" : (selGeo.type === "hosting" ? "am" : "gr")}>{selGeo.type}</Badge></div>
                <div>Timezone</div><div className="mono">UTC{selGeo.tz >= 0 ? "+" : ""}{selGeo.tz}</div>
                <div>Campaign reuse</div><div className="mono">{3 + (hashStr(selGeo.ip) % 9)} linked cases</div>
              </div>
              {selAlert ? (
                <div style={{ marginTop: 10 }}>
                  <div className="chip">{selAlert.id}</div>
                  <div className="chip">{selAlert.category}</div>
                  <div className="chip">score {selAlert.score}</div>
                </div>
              ) : null}
            </div>
          ) : <Empty t="Click any plotted point to inspect its attribution" />}
        </Panel>

        <Panel title="Top origin countries" sub="threat concentration" bodyStyle={{ padding: "6px 14px 12px" }}>
          {byCountry.map((c) => (
            <div key={c[0]} style={{ marginBottom: 9 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }}><span>{c[0]}</span><b className="mono" style={{ color: "var(--cy)" }}>{c[1]}</b></div>
              <div style={{ marginTop: 4 }}><Meter v={(c[1] / byCountry[0][1]) * 100} tone="cy" h={5} /></div>
            </div>
          ))}
        </Panel>

        <Panel title="10-stage attribution pipeline" sub="HUNTERTRACE methodology">
          {["Header extraction (RFC 2822)", "Webmail IP leak detection", "IP classification (VPN/Tor/Proxy)", "VPN backtrack (12 techniques)", "Real IP extraction", "Enrichment (WHOIS/ASN/host)", "Threat intelligence & correlation", "Geolocation (city, IPv4+IPv6)", "Bayesian multi-signal fusion", "Attribution analysis & packaging"].map((s, i) => (
            <div className="mrow" key={s} style={{ padding: "5px 0" }}>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--cy)", width: 18 }}>{pad(i + 1)}</span>
              <div style={{ flex: 1, fontSize: 11.3 }}>{s}</div>
              <span style={{ color: "var(--gr)", display: "inline-flex" }}><Icon n="check" s={12} /></span>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  );
}

function GraphPage({ toast }) {
  const [groups, setGroups] = useState(4);
  const [sel, setSel] = useState(null);
  const [anomalies, setAnomalies] = useState(false);
  const W = 760, H = 460, R = 175;
  const GC = ["#22d3ee", "#34d399", "#fb7185", "#fbbf24", "#a78bfa", "#60a5fa"];

  const layout = useMemo(() => GRAPH_NODES.map((n, i) => {
    const same = GRAPH_NODES.filter((m) => (m.g % groups) === (n.g % groups));
    const idx = same.indexOf(n);
    const a = (i / GRAPH_NODES.length) * Math.PI * 2 - Math.PI / 2 + (n.g % groups) * 0.12;
    const rad = R - (n.g % groups) * 26 + (idx % 2) * 16;
    return { id: n.id, type: n.type, weight: n.weight, gg: n.g % groups, x: W / 2 + Math.cos(a) * rad, y: H / 2 + Math.sin(a) * rad * 0.82 };
  }), [groups]);

  const byId = {};
  layout.forEach((n) => { byId[n.id] = n; });

  const recluster = () => {
    const next = groups >= 6 ? 2 : groups + 1;
    setGroups(next);
    setAnomalies(true);
    setTimeout(() => setAnomalies(false), 2600);
    toast("Unsupervised peer-group clustering re-run (Louvain, " + next + " communities)");
  };
  const selNode = sel ? byId[sel] : null;
  const selDeg = sel ? GRAPH_EDGES.filter((e) => e.s === sel || e.t === sel) : [];

  return (
    <div className="grid fu" style={{ gridTemplateColumns: "1.5fr 1fr", gap: 12 }}>
      <Panel title="Social graph viewer" sub="sender–receiver interaction network · peer-group anomaly detection"
        right={
          <div style={{ display: "flex", gap: 6 }}>
            <button className="btn sm" onClick={recluster}><Icon n="refresh" s={12} />Re-cluster</button>
            <button className="btn sm" onClick={() => setAnomalies(!anomalies)}><Icon n="eye" s={12} />{anomalies ? "Hide" : "Show"} anomalies</button>
          </div>
        }>
        <svg viewBox={"0 0 " + W + " " + H} style={{ width: "100%", height: 470, display: "block" }}>
          <defs>
            <radialGradient id="ng"><stop offset="0%" stopColor="#22d3ee" stopOpacity="0.22" /><stop offset="100%" stopColor="#22d3ee" stopOpacity="0" /></radialGradient>
          </defs>
          <circle cx={W / 2} cy={H / 2} r={R + 40} fill="url(#ng)" />
          {GRAPH_EDGES.map((e, i) => {
            const s = byId[e.s], t = byId[e.t];
            if (!s || !t) return null;
            const bad = s.type === "suspect" || t.type === "suspect";
            return (
              <line key={i} className={bad ? "edgeflow" : undefined} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                stroke={bad ? "#fb7185" : "#2f4a5e"} strokeWidth={0.6 + e.w * 0.32} strokeOpacity={bad ? 0.75 : 0.4} />
            );
          })}
          {layout.map((n) => {
            const c = n.type === "suspect" ? "#fb7185" : (n.type === "vip" ? "#fbbf24" : GC[n.gg]);
            const r = 6 + n.weight * 0.16;
            const on = sel === n.id;
            return (
              <g key={n.id} style={{ cursor: "pointer" }} onClick={() => setSel(n.id)}>
                {anomalies && n.type === "suspect" ? (
                  <circle cx={n.x} cy={n.y} r={r + 10} fill="none" stroke="#fb7185" strokeOpacity="0.5">
                    <animate attributeName="r" values={(r + 6) + ";" + (r + 18) + ";" + (r + 6)} dur="2s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.55;0;0.55" dur="2s" repeatCount="indefinite" />
                  </circle>
                ) : null}
                <circle cx={n.x} cy={n.y} r={r} fill={c} fillOpacity={on ? 1 : 0.82} stroke={on ? "#fff" : "#05080e"} strokeWidth={on ? 2 : 1.4} style={{ transition: "fill-opacity .2s" }} />
                <text x={n.x} y={n.y + r + 12} textAnchor="middle" fontSize="9" fill={on ? "#fff" : "#8aa2b4"} fontFamily="JetBrains Mono, monospace">
                  {n.id.length > 26 ? n.id.slice(0, 24) + "…" : n.id}
                </text>
              </g>
            );
          })}
        </svg>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 10.5, color: "var(--mu)" }}>
          <span style={{ display: "flex", alignItems: "center", gap: 5 }}><span className="dot" style={{ background: "#fb7185" }} />suspect / adversary</span>
          <span style={{ display: "flex", alignItems: "center", gap: 5 }}><span className="dot" style={{ background: "#fbbf24" }} />VIP user</span>
          <span style={{ display: "flex", alignItems: "center", gap: 5 }}><span className="dot" style={{ background: "#22d3ee" }} />internal peer group</span>
          <span style={{ display: "flex", alignItems: "center", gap: 5 }}><span style={{ width: 16, height: 2, background: "#2f4a5e", display: "inline-block" }} />communication edge</span>
        </div>
      </Panel>

      <div className="grid">
        <Panel title="Node inspector" sub={selNode ? selNode.id : "select a node"}>
          {selNode ? (
            <div className="kv fi">
              <div>Identity</div><div className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>{selNode.id}</div>
              <div>Class</div><div><Badge tone={selNode.type === "suspect" ? "rd" : (selNode.type === "vip" ? "am" : "cy")}>{selNode.type}</Badge></div>
              <div>Peer group</div><div className="mono">cluster {selNode.gg}</div>
              <div>Degree</div><div className="mono">{selDeg.length} edges · weight {selDeg.reduce((s, e) => s + e.w, 0)}</div>
              <div>Message volume</div><div className="mono">{selNode.weight * 7}</div>
              <div>Association anomaly</div>
              <div><b style={{ color: selNode.type === "suspect" ? "var(--rd)" : "var(--gr)" }}>
                {((selNode.type === "suspect" ? 78 + (hashStr(selNode.id) % 18) : 4 + (hashStr(selNode.id) % 14)) / 100).toFixed(2)}
              </b></div>
              <div>First seen</div><div className="mono" style={{ fontSize: 11 }}>2025-0{(hashStr(selNode.id) % 5) + 1}-1{hashStr(selNode.id) % 9}</div>
            </div>
          ) : <Empty t="Click a node to inspect its peer group and anomaly score" />}
        </Panel>

        <Panel title="Peer-group analysis" sub="unsupervised clustering results">
          {Array.from({ length: groups }, (x, i) => {
            const mem = layout.filter((n) => n.gg === i);
            const susp = mem.filter((n) => n.type === "suspect").length;
            return (
              <div key={i} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.5 }}>
                  <span><span className="dot" style={{ background: GC[i], display: "inline-block", marginRight: 6 }} />Cluster {i} · {mem.length} nodes</span>
                  <Badge tone={susp ? "rd" : "gr"}>{susp ? susp + " suspect" : "clean"}</Badge>
                </div>
                <div style={{ marginTop: 4 }}><Meter v={(mem.length / GRAPH_NODES.length) * 100} tone={susp ? "rd" : "gr"} h={5} /></div>
              </div>
            );
          })}
        </Panel>

        <Panel title="VIP deviation watch" sub="behavioural baseline drift">
          {[["s.rivera (CFO)", 12, "gr"], ["finance-grp", 34, "am"], ["j.whitaker", 61, "rd"], ["a.kowalski", 8, "gr"]].map((v) => (
            <div className="mrow" key={v[0]}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11.5 }}>{v[0]}</div>
                <div style={{ marginTop: 4 }}><Meter v={v[1]} tone={v[2]} h={5} /></div>
              </div>
              <b className="mono" style={{ color: TONE[v[2]] }}>{v[1]}%</b>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  );
}

function Forensics({ toast, cases }) {
  const [cid, setCid] = useState(CASES[0].id);
  const [tampered, setTampered] = useState(null);
  const [verify, setVerify] = useState({});
  const c = cases.filter((x) => x.id === cid)[0] || cases[0];

  const recompute = async (e) => {
    const base = await sha256(e.name + e.sha);
    const isTampered = tampered === e.id;
    const recomputed = isTampered ? await sha256(e.name + "::TAMPERED::") : base;
    const ok = recomputed === base && !isTampered;
    const next = {};
    Object.keys(verify).forEach((k) => { next[k] = verify[k]; });
    next[e.id] = { ok: ok, hash: recomputed, at: new Date().toISOString() };
    setVerify(next);
    toast(ok ? "Hash verified — chain of custody intact" : "Hash mismatch — evidence tampered");
  };

  return (
    <div className="grid fu" style={{ gridTemplateColumns: "260px 1fr", gap: 12 }}>
      <Panel title="Case selector" sub={cases.length + " cases"} bodyStyle={{ padding: 8 }}>
        <div className="scroll" style={{ maxHeight: 560 }}>
          {cases.map((x) => (
            <div key={x.id} onClick={() => setCid(x.id)}
              style={{ padding: "9px 10px", borderRadius: 9, cursor: "pointer", marginBottom: 5, border: "1px solid " + (x.id === cid ? "rgba(34,211,238,.45)" : "var(--ln)"), background: x.id === cid ? "rgba(34,211,238,.09)" : "transparent" }}>
              <div className="mono" style={{ fontSize: 10, color: "var(--cy)" }}>{x.id}</div>
              <div style={{ fontSize: 11.5, marginTop: 2, lineHeight: 1.4 }}>{x.title}</div>
              <div style={{ display: "flex", gap: 5, marginTop: 6 }}>
                <Badge tone={x.priority === "P1" ? "rd" : (x.priority === "P2" ? "am" : "mu")}>{x.priority}</Badge>
                <Badge tone="mu">{x.emails} mails</Badge>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid">
        <Panel title={c.title} sub={c.id + " · opened " + new Date(c.created).toDateString() + " · analyst " + c.analyst}
          right={
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn sm" onClick={() => toast("Evidence package (.zip + manifest + hashes) queued for export")}>Export package</button>
              <button className="btn sm p" onClick={() => toast("Report generated for " + c.id)}>Generate report</button>
            </div>
          }>
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 10 }}>
            {[["Status", c.status, "cy"], ["Priority", c.priority, "rd"], ["Emails in scope", c.emails, "bl"], ["IOCs collected", c.iocs, "vi"], ["Attribution confidence", c.confidence + "%", "am"]].map((k) => (
              <div key={k[0]} style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 9, padding: 10 }}>
                <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase" }}>{k[0]}</div>
                <div className="mono" style={{ fontSize: 15, color: TONE[k[2]], marginTop: 4 }}>{k[1]}</div>
              </div>
            ))}
            <div style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 9, padding: 10 }}>
              <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase" }}>Adversary</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>{c.actor}</div>
            </div>
          </div>
        </Panel>

        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Panel title="Investigation timeline" sub="end-to-end event reconstruction" bodyStyle={{ padding: "8px 14px 12px" }}>
            <div className="scroll" style={{ maxHeight: 320 }}>
              {TIMELINE.map((t, i) => (
                <div className="hop" key={i}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                    <span className="dot" style={{ background: { signal: "#fbbf24", hop: "#a78bfa", auth: "#fb7185", detect: "#22d3ee", agent: "#34d399", action: "#60a5fa", case: "#ffffff" }[t.k], marginTop: 5 }} />
                    {i < TIMELINE.length - 1 ? <div style={{ width: 1, flex: 1, background: "var(--ln2)", minHeight: 14 }} /> : null}
                  </div>
                  <div>
                    <div style={{ fontSize: 11.8, fontWeight: 550 }}>{t.t}</div>
                    <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 2 }}>{t.d}</div>
                  </div>
                  <span className="mono" style={{ fontSize: 9.8, color: "#6f8698", whiteSpace: "nowrap" }}>{t.ts.slice(11, 19)}</span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Chain of custody" sub="SHA-256 verification of collected evidence"
            right={
              <button className="btn sm d" onClick={() => { const t = tampered ? null : EVIDENCE[1].id; setTampered(t); toast(t ? "Simulated tampering on " + EVIDENCE[1].name : "Tamper simulation cleared"); }}>
                <Icon n="warn" s={12} />{tampered ? "Undo tamper" : "Simulate tamper"}
              </button>
            } bodyStyle={{ padding: 0 }}>
            <div className="scroll" style={{ maxHeight: 320 }}>
              <table>
                <thead><tr><Th>ID</Th><Th>Evidence</Th><Th>SHA-256</Th><Th>Status</Th><Th></Th></tr></thead>
                <tbody>
                  {EVIDENCE.map((e) => {
                    const v = verify[e.id];
                    const bad = v && !v.ok;
                    return (
                      <tr key={e.id}>
                        <td className="mono" style={{ fontSize: 10, color: "var(--cy)" }}>{e.id}</td>
                        <td>
                          <div style={{ fontSize: 11.5 }}>{e.name}</div>
                          <div style={{ fontSize: 10, color: "var(--mu)" }}>{e.kind} · {e.size} · {e.custodian}</div>
                        </td>
                        <td className="mono" style={{ fontSize: 9.5, color: bad ? "#ffc2cd" : "#8aa2b4", maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {bad ? "!= " + e.sha.slice(0, 14) + "…" : e.sha.slice(0, 20) + "…"}
                        </td>
                        <td>{v ? (v.ok ? <Badge tone="gr">intact</Badge> : <Badge tone="rd">tampered</Badge>) : <Badge tone="mu">unverified</Badge>}</td>
                        <td><button className="btn sm" onClick={() => recompute(e)}><Icon n="lock" s={11} />Verify</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>

        <Panel title="Case IOCs & correlation" sub="infrastructure reuse across campaigns" bodyStyle={{ padding: 0 }}>
          <table>
            <thead><tr><Th>Type</Th><Th>Value</Th><Th>Severity</Th><Th>First seen</Th><Th>Linked cases</Th><Th>Sources</Th></tr></thead>
            <tbody>
              {IOC_LIST.filter((i, k) => (k % 2) === (c.id.charCodeAt(7) % 2)).map((i) => (
                <tr key={i.value}>
                  <td><Badge tone="vi">{i.type}</Badge></td>
                  <td className="mono" style={{ fontSize: 10.5 }}>{i.value}</td>
                  <td><Badge tone={sevTone(i.sev)}>{i.sev}</Badge></td>
                  <td className="mono" style={{ fontSize: 10.5, color: "var(--mu)" }}>{i.seen}</td>
                  <td className="mono">{i.cases}</td>
                  <td style={{ fontSize: 10.5, color: "var(--mu)" }}>{i.src}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  );
}

function Investigations({ cases, setCases, toast, sb }) {
  const [openNew, setOpenNew] = useState(false);
  const [form, setForm] = useState({ title: "", priority: "P2", analyst: "M. Okafor", scope: "finance department" });
  const cols = [["triage", "Triage", "am"], ["investigating", "Investigating", "cy"], ["review", "Review", "vi"], ["closed", "Closed", "mu"]];

  const create = async () => {
    if (!form.title.trim()) { toast("Case title required"); return; }
    const id = "CASE-" + (2292 + cases.length);
    const nc = { id: id, title: form.title, status: "triage", priority: form.priority, analyst: form.analyst, created: new Date().toISOString(), emails: 0, iocs: 0, actor: "Unattributed", confidence: 0, scope: form.scope };
    setCases((p) => [nc].concat(p));
    setOpenNew(false);
    setForm(Object.assign({}, form, { title: "" }));
    if (sb.status === "connected" && sb.client) {
      try {
        const r = await sb.client.from("cases").insert({ ref: id, title: nc.title, status: "triage", priority: nc.priority, scope: { text: form.scope } });
        if (r.error) throw r.error;
        toast("Case " + id + " created (Supabase + local)");
        return;
      } catch (e) {
        toast("Created locally; Supabase insert failed: " + (e.message || e));
        return;
      }
    }
    toast("Case " + id + " created in demo mode");
  };

  const move = (id, s) => {
    setCases((p) => p.map((c) => (c.id === id ? Object.assign({}, c, { status: s }) : c)));
    toast(id + " → " + s);
  };

  return (
    <div className="grid fu">
      <Panel title="Investigation dashboard" sub="case management · evidence tracking · correlation"
        right={<button className="btn p sm" onClick={() => setOpenNew(true)}><Icon n="plus" s={12} c="#eafeff" />New case</button>}
        bodyStyle={{ padding: 12 }}>
        <div className="kan">
          {cols.map((col) => (
            <div key={col[0]}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 9 }}>
                <span className="dot" style={{ background: TONE[col[2]] }} />
                <b style={{ fontSize: 11.5, letterSpacing: 0.5 }}>{col[1]}</b>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--mu)" }}>{cases.filter((c) => c.status === col[0]).length}</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, minHeight: 80 }}>
                {cases.filter((c) => c.status === col[0]).map((c, ci) => (
                  <div className="kcard fu" key={c.id} style={{ animationDelay: ci * 40 + "ms" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 6 }}>
                      <span className="mono" style={{ fontSize: 9.8, color: "var(--cy)" }}>{c.id}</span>
                      <Badge tone={c.priority === "P1" ? "rd" : (c.priority === "P2" ? "am" : "mu")}>{c.priority}</Badge>
                    </div>
                    <div style={{ fontSize: 11.8, marginTop: 5, lineHeight: 1.45 }}>{c.title}</div>
                    <div style={{ fontSize: 10, color: "var(--mu)", marginTop: 6 }}>{c.analyst} · {c.emails} emails · {c.iocs} IOCs</div>
                    {c.confidence > 0 ? (
                      <div style={{ marginTop: 7 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9.5, color: "var(--mu)" }}><span>attribution</span><span className="mono">{c.confidence}%</span></div>
                        <div style={{ marginTop: 3 }}><Meter v={c.confidence} tone={c.confidence > 70 ? "rd" : "am"} h={4} /></div>
                      </div>
                    ) : null}
                    <div style={{ display: "flex", gap: 5, marginTop: 9, flexWrap: "wrap" }}>
                      {cols.filter((x) => x[0] !== col[0]).map((x) => (
                        <button key={x[0]} className="btn sm" style={{ padding: "3px 7px", fontSize: 10 }} onClick={() => move(c.id, x[0])}>→ {x[1]}</button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel title="Investigation workflow" sub="5-stage lifecycle per architecture spec">
          {[["1. Create case", "Assign analysts, set priority, define scope", 100], ["2. Evidence collection", "Import .eml/.msg/mbox · extract headers · hash for custody", 100], ["3. Analysis", "AI detection · geolocation · IOC enrichment · timeline", 88], ["4. Correlation", "Link cases/campaigns · infrastructure reuse · adversary profiles", 64], ["5. Reporting", "PDF/HTML generation · evidence packages · exec summaries", 41]].map((w, i) => (
            <div key={i} style={{ marginBottom: 11 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.8 }}><b>{w[0]}</b><span className="mono" style={{ color: "var(--cy)", fontSize: 10.5 }}>{w[2]}%</span></div>
              <div style={{ fontSize: 10.5, color: "var(--mu)", margin: "2px 0 5px" }}>{w[1]}</div>
              <Meter v={w[2]} tone={w[2] > 80 ? "gr" : (w[2] > 50 ? "cy" : "am")} h={5} />
            </div>
          ))}
        </Panel>
        <Panel title="Breach intelligence" sub="Have I Been Pwned cross-reference">
          {[["j.whitaker@northwind-logistics.com", 3, "Collection #1, LinkedIn, Canva"], ["s.rivera@northwind-logistics.com", 1, "Collection #1"], ["finance@northwind-logistics.com", 5, "Collection #1-5, Verifications.io"], ["m.okafor@northwind-logistics.com", 0, "—"], ["hr@northwind-logistics.com", 2, "Collection #2, Wattpad"]].map((b) => (
            <div className="mrow" key={b[0]}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 10.8, overflow: "hidden", textOverflow: "ellipsis" }}>{b[0]}</div>
                <div style={{ fontSize: 10, color: "var(--mu)" }}>{b[2]}</div>
              </div>
              <Badge tone={b[1] === 0 ? "gr" : (b[1] > 3 ? "rd" : "am")}>{b[1]} breach{b[1] === 1 ? "" : "es"}</Badge>
            </div>
          ))}
          <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--mu)" }}>Requires <span className="mono" style={{ color: "var(--am)" }}>HIBP_API_KEY</span>. PII is masked before persistence (GDPR/CCPA/HIPAA readiness).</div>
        </Panel>
      </div>

      {openNew ? (
        <React.Fragment>
          <div className="ov" onClick={() => setOpenNew(false)} />
          <div className="modal">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
              <b style={{ fontSize: 14 }}>Create investigation</b>
              <button className="btn sm" onClick={() => setOpenNew(false)}><Icon n="x" s={12} /></button>
            </div>
            <div style={{ display: "grid", gap: 10 }}>
              <div>
                <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 4 }}>Title</div>
                <input className="inps" style={{ width: "100%" }} value={form.title} onChange={(e) => setForm(Object.assign({}, form, { title: e.target.value }))} placeholder="e.g. Credential harvest wave targeting APAC finance" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div>
                  <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 4 }}>Priority</div>
                  <select className="inps" style={{ width: "100%" }} value={form.priority} onChange={(e) => setForm(Object.assign({}, form, { priority: e.target.value }))}>
                    {["P1", "P2", "P3", "P4"].map((p) => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 4 }}>Lead analyst</div>
                  <select className="inps" style={{ width: "100%" }} value={form.analyst} onChange={(e) => setForm(Object.assign({}, form, { analyst: e.target.value }))}>
                    {["M. Okafor", "L. Chen", "S. Rivera", "A. Kowalski"].map((p) => <option key={p}>{p}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 4 }}>Scope</div>
                <input className="inps" style={{ width: "100%" }} value={form.scope} onChange={(e) => setForm(Object.assign({}, form, { scope: e.target.value }))} />
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
              <button className="btn" onClick={() => setOpenNew(false)}>Cancel</button>
              <button className="btn p" onClick={create}>Create case</button>
            </div>
          </div>
        </React.Fragment>
      ) : null}
    </div>
  );
}

function IocIntel({ toast }) {
  const [q, setQ] = useState("");
  const [t, setT] = useState("all");
  const [enriching, setEnriching] = useState(null);
  const [enrich, setEnrich] = useState({});
  const list = IOC_LIST.filter((i) => (t === "all" || i.type === t) && (q === "" || i.value.toLowerCase().indexOf(q.toLowerCase()) >= 0));

  const runEnrich = (v) => {
    setEnriching(v);
    setTimeout(() => {
      const h = hashStr(v);
      const next = {};
      Object.keys(enrich).forEach((k) => { next[k] = enrich[k]; });
      next[v] = {
        vt: (12 + (h % 58)) + "/72", abuse: 40 + (h % 60),
        ipinfo: ["hosting", "vpn", "residential", "business"][h % 4],
        urlhaus: h % 3 === 0, openphis: h % 4 === 0, urlscan: 60 + (h % 40), hibp: h % 5,
        fetched: new Date().toISOString()
      };
      setEnrich(next);
      setEnriching(null);
      toast("Enrichment complete across 7 feeds (parallel)");
    }, 750);
  };

  return (
    <div className="grid fu">
      <Panel title="IOC intelligence" sub="extracted indicators, cross-feed enrichment and case correlation"
        right={
          <div style={{ display: "flex", gap: 8 }}>
            <input className="inps" placeholder="Search indicators…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 210 }} />
            <select className="inps" value={t} onChange={(e) => setT(e.target.value)}>
              {["all", "ip", "domain", "url", "sha256", "email"].map((x) => <option key={x}>{x}</option>)}
            </select>
            <button className="btn sm" onClick={() => {
              const csv = "type,value,severity,confidence,first_seen,linked_cases,source\n" + list.map((i) => [i.type, i.value, i.sev, i.conf, i.seen, i.cases, '"' + i.src + '"'].join(",")).join("\n");
              download("ioc-export.csv", csv, "text/csv");
              toast("CSV export downloaded");
            }}>Export CSV</button>
          </div>
        } bodyStyle={{ padding: 0 }}>
        <div className="scroll" style={{ maxHeight: "calc(100vh - 250px)" }}>
          <table>
            <thead><tr><Th>Type</Th><Th>Indicator</Th><Th>Severity</Th><Th>Confidence</Th><Th>First seen</Th><Th>Cases</Th><Th>Primary source</Th><Th></Th></tr></thead>
            <tbody>
              {list.map((i) => {
                const e = enrich[i.value];
                return (
                  <React.Fragment key={i.value}>
                    <tr className="cl" onClick={() => runEnrich(i.value)}>
                      <td><Badge tone="vi">{i.type}</Badge></td>
                      <td className="mono" style={{ fontSize: 10.5, maxWidth: 330, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{i.value}</td>
                      <td><Badge tone={sevTone(i.sev)}>{i.sev}</Badge></td>
                      <td>
                        <div style={{ display: "flex", gap: 7, alignItems: "center", width: 96 }}>
                          <span className="mono" style={{ fontSize: 11 }}>{i.conf}</span>
                          <div style={{ flex: 1 }}><Meter v={i.conf} tone={i.conf > 80 ? "rd" : (i.conf > 60 ? "am" : "cy")} h={4} /></div>
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 10.5, color: "var(--mu)" }}>{i.seen}</td>
                      <td className="mono">{i.cases}</td>
                      <td style={{ fontSize: 10.5, color: "var(--mu)" }}>{i.src}</td>
                      <td onClick={(ev) => ev.stopPropagation()}>
                        <div style={{ display: "flex", gap: 4 }}>
                          <button className="btn sm" onClick={() => runEnrich(i.value)} disabled={enriching === i.value}>
                            {enriching === i.value ? <span className="spin"><Icon n="refresh" s={11} /></span> : "Enrich"}
                          </button>
                          <button className="btn sm" onClick={() => { copy(i.value); toast("Copied"); }}><Icon n="copy" s={11} /></button>
                        </div>
                      </td>
                    </tr>
                    {e ? (
                      <tr className="fi">
                        <td colSpan={8} style={{ background: "#08111b", padding: 0 }}>
                          <div style={{ padding: "10px 14px" }}>
                            <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase", marginBottom: 7 }}>Parallel feed enrichment · cached {ago(e.fetched)} · TTL 24 h</div>
                            <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
                              <span className="chip">VirusTotal: <b>{e.vt} detections</b></span>
                              <span className="chip">AbuseIPDB: <b>confidence {e.abuse}</b></span>
                              <span className="chip">IPinfo: <b>{e.ipinfo}</b></span>
                              <span className="chip" style={{ borderColor: e.urlhaus ? "rgba(251,113,133,.4)" : "var(--ln2)", color: e.urlhaus ? "#ffc2cd" : "#a9c3d4" }}>URLhaus: <b>{e.urlhaus ? "LISTED" : "not listed"}</b></span>
                              <span className="chip" style={{ borderColor: e.openphis ? "rgba(251,113,133,.4)" : "var(--ln2)", color: e.openphis ? "#ffc2cd" : "#a9c3d4" }}>OpenPhish: <b>{e.openphis ? "LISTED" : "not listed"}</b></span>
                              <span className="chip">URLscan: <b>score {e.urlscan}</b></span>
                              <span className="chip">HIBP: <b>{e.hibp} breaches</b></span>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          {list.length ? null : <Empty t="No indicators match the query" />}
        </div>
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(230px,1fr))", gap: 12 }}>
        <Panel title="Connected feeds" sub="daily auto-refresh + TTL cache">
          {[["VirusTotal", "gr"], ["AbuseIPDB", "gr"], ["IPinfo", "gr"], ["OpenPhish", "gr"], ["URLhaus", "gr"], ["URLscan.io", "am"], ["Recorded Future", "mu"], ["Have I Been Pwned", "am"]].map((f) => (
            <div className="mrow" key={f[0]}>
              <span className="dot" style={{ background: TONE[f[1]] }} />
              <div style={{ flex: 1, fontSize: 11.5 }}>{f[0]}</div>
              <Badge tone={f[1]}>{f[1] === "gr" ? "live" : (f[1] === "am" ? "key needed" : "inactive")}</Badge>
            </div>
          ))}
        </Panel>
        <Panel title="Feed refresh status" sub="last sync window">
          {[["OpenPhish", "2 min ago", 100], ["URLhaus", "14 min ago", 100], ["VirusTotal", "1 h ago", 92], ["AbuseIPDB", "3 h ago", 78], ["Recorded Future", "26 h ago", 22]].map((f) => (
            <div key={f[0]} style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11.3 }}><span>{f[0]}</span><span className="mono" style={{ fontSize: 10, color: "var(--mu)" }}>{f[1]}</span></div>
              <div style={{ marginTop: 4 }}><Meter v={f[2]} tone={f[2] > 80 ? "gr" : (f[2] > 40 ? "am" : "rd")} h={5} /></div>
            </div>
          ))}
        </Panel>
        <Panel title="Extraction coverage" sub="IOC types and methods" bodyStyle={{ padding: "4px 14px 12px" }}>
          <div className="scroll" style={{ maxHeight: 220 }}>
            <table>
              <tbody>
                {[["IP addresses", "Header parsing + body regex", "GeoIP, WHOIS, AbuseIPDB"], ["Domains", "URL parsing + regex", "WHOIS, domain age, DNSSEC"], ["URLs", "Link extraction + HTML parsing", "Redirect analysis, VirusTotal"], ["Email addresses", "Header + body regex", "Breach lookup, provider ID"], ["File hashes", "MD5 / SHA1 / SHA256", "VirusTotal, hash intelligence"]].map((r) => (
                  <tr key={r[0]}>
                    <td style={{ fontSize: 11.5, fontWeight: 550 }}>{r[0]}</td>
                    <td style={{ fontSize: 10.5, color: "var(--mu)" }}>{r[1]}<div style={{ marginTop: 2, color: "#7f9aad" }}>↳ {r[2]}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function Reports({ cases, alerts, toast }) {
  const [cid, setCid] = useState(cases[0] ? cases[0].id : "");
  const [fmtType, setFmt] = useState("markdown");
  const c = cases.filter((x) => x.id === cid)[0] || cases[0] || {};
  const relAlerts = alerts.slice(0, 6);
  const body = useMemo(() => {
    const now = new Date().toISOString();
    const malicious = relAlerts.filter((a) => a.verdict === "MALICIOUS").length;
    const meanScore = Math.round(relAlerts.reduce((s, a) => s + a.score, 0) / Math.max(1, relAlerts.length));
    const first = relAlerts[0];
    const originLine = first ? (first.geo.city + ", " + first.geo.country + " (" + first.geo.org + ")") : "n/a";
    const nodeLine = first ? first.geo.type.toUpperCase() : "n/a";
    const ipLine = first ? first.ip : "n/a";
    return "# FORENSIC INTELLIGENCE REPORT\n" +
      "**Case:** " + (c.id || "CASE-0000") + " — " + (c.title || "Untitled") + "\n" +
      "**Classification:** CONFIDENTIAL / TLP:AMBER\n" +
      "**Generated:** " + now + "\n" +
      "**Lead analyst:** " + (c.analyst || "unassigned") + "  ·  **Priority:** " + (c.priority || "P3") + "  ·  **Status:** " + (c.status || "open") + "\n\n" +
      "## 1. Executive summary\n" +
      "A coordinated phishing campaign targeting the finance function was identified by the AI-powered\n" +
      "detection platform. " + (c.emails || 0) + " related messages were ingested, of which " + malicious + "\n" +
      "were classified MALICIOUS by the fused multi-agent verdict (mean risk score " + meanScore + "/100).\n" +
      "Attribution confidence: " + (c.confidence || 0) + "% — adversary profile: " + (c.actor || "unattributed") + ".\n\n" +
      "## 2. Detection methodology\n" +
      "| Layer | Technique | Contribution |\n|---|---|---|\n" +
      "| L1 | SPF/DKIM/DMARC, blacklists, rule engine | Signature hits |\n" +
      "| L2 | TF-IDF + Logistic Regression (92.44% acc), XGBoost | Interpretable features |\n" +
      "| L3 | DistilBERT (99.78% acc), BiLSTM (98.31% acc) | Contextual semantics |\n" +
      "| L4 | 5-agent LLM reasoning with PPO-fused weights | Deep analysis |\n\n" +
      "## 3. Indicators of compromise\n" +
      IOC_LIST.slice(0, 8).map((i) => "- `" + i.value + "` — " + i.type.toUpperCase() + " · severity " + i.sev + " · confidence " + i.conf + "% · source " + i.src).join("\n") + "\n\n" +
      "## 4. Geolocation & attribution\n" +
      "Multi-signal Bayesian fusion (HUNTERTRACE) over 8 orthogonal signals produced:\n" +
      "- Origin netblock: `" + ipLine + "` → " + originLine + "\n" +
      "- Node classification: " + nodeLine + "\n" +
      "- Impossible-travel check: velocity above the 900 km/h threshold confirmed on 3 sender identities\n" +
      "- Country-level accuracy 52.8% / region-level 56.6%\n\n" +
      "## 5. Timeline of events\n" +
      TIMELINE.map((t) => "- `" + t.ts + "` — " + t.t + ": " + t.d).join("\n") + "\n\n" +
      "## 6. Evidence & chain of custody\n" +
      EVIDENCE.map((e) => "- " + e.id + " · " + e.kind + " · " + e.name + " (" + e.size + ") · SHA-256 `" + e.sha + "` · custodian " + e.custodian).join("\n") + "\n" +
      "All artefacts are stored in the immutable forensic archive bucket with cryptographic hashing\nand tamper-evident audit logging.\n\n" +
      "## 7. Recommended actions\n" +
      "1. Block sender domains and netblocks at the perimeter and MTA.\n" +
      "2. Force credential reset + MFA re-enrolment for the " + (c.emails || 0) + " targeted recipients.\n" +
      "3. Recall quarantined sibling messages from all mailboxes.\n" +
      "4. Retrain the adversarial agent on the observed evasion variants.\n" +
      "5. Share IOCs with the sector ISAC and update internal blocklists.\n\n" +
      "## 8. Compliance notes\n" +
      "PII masked prior to persistence. Processing lawful under GDPR Art. 6(1)(f) (security of processing),\nCCPA and HIPAA safeguards. Data residency: EU-West. Breach notification workflow armed.\n\n" +
      "*Generated by SentinelGrid — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform.*";
  }, [c, relAlerts]);

  return (
    <Panel className="fu" title="Report generator" sub="automated forensic & executive reporting"
      right={
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <select className="inps" value={cid} onChange={(e) => setCid(e.target.value)}>
            {cases.map((x) => <option key={x.id} value={x.id}>{x.id} — {x.title.slice(0, 42)}</option>)}
          </select>
          <div className="tabs">
            {["markdown", "html", "pdf"].map((f) => (
              <button key={f} className={"tab" + (fmtType === f ? " on" : "")} onClick={() => setFmt(f)}>{f}</button>
            ))}
          </div>
          <button className="btn sm" onClick={() => { copy(body); toast("Report copied to clipboard"); }}><Icon n="copy" s={12} />Copy</button>
          <button className="btn sm" onClick={() => { download((c.id || "report") + ".md", body); toast("Downloaded " + (c.id || "report") + ".md"); }}><Icon n="down" s={12} />Download</button>
          <button className="btn sm p" onClick={() => window.print()}><Icon n="print" s={12} c="#eafeff" />Print / PDF</button>
        </div>
      }>
      <div className="grid" style={{ gridTemplateColumns: "230px 1fr", gap: 12 }}>
        <div>
          <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase", marginBottom: 7 }}>Report templates</div>
          {["Forensic case report", "Executive summary", "IOC / blocklist feed", "Attribution dossier", "Compliance & GDPR annex", "Board risk briefing"].map((t, i) => (
            <div key={t} onClick={() => toast("Template loaded: " + t)}
              style={{ padding: "8px 10px", borderRadius: 8, border: "1px solid " + (i === 0 ? "rgba(34,211,238,.4)" : "var(--ln)"), background: i === 0 ? "rgba(34,211,238,.07)" : "transparent", marginBottom: 6, cursor: "pointer", fontSize: 11.5 }}>{t}</div>
          ))}
          <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase", margin: "14px 0 7px" }}>Sections</div>
          {["Executive summary", "Methodology", "IOCs", "Geolocation", "Timeline", "Evidence", "Actions", "Compliance"].map((s, i) => (
            <div className="mrow" key={s} style={{ padding: "5px 0" }}>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--cy)" }}>{pad(i + 1)}</span>
              <div style={{ flex: 1, fontSize: 11 }}>{s}</div>
              <span style={{ color: "var(--gr)", display: "inline-flex" }}><Icon n="check" s={11} /></span>
            </div>
          ))}
        </div>
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 7 }}>
            <div style={{ fontSize: 9.5, letterSpacing: 1, color: "var(--mu)", textTransform: "uppercase" }}>Preview · {fmtType}</div>
            <div style={{ display: "flex", gap: 6 }}>
              <span className="chip">{body.split(/\s+/).length} words</span>
              <span className="chip">{body.length} chars</span>
              <span className="chip">hash {String(hashStr(body)).slice(0, 8)}</span>
            </div>
          </div>
          <code className="blk" style={{ maxHeight: "calc(100vh - 330px)" }}>{body}</code>
        </div>
      </div>
    </Panel>
  );
}

function Architecture() {
  const layers = [
    ["Presentation layer", "Analyst Dashboard · Alert Console · Forensic Workbench · Report Generator", "cy"],
    ["API gateway & orchestration", "FastAPI / GraphQL / gRPC · authentication · rate limiting · routing", "bl"],
    ["Multi-agent orchestration engine", "LangGraph · Text · URL · Metadata · Adversarial · Explanation Simplifier", "vi"],
    ["Core detection & intelligence", "AI Threat Detection · Geolocation Intelligence · Forensic Intelligence", "rd"],
    ["Data ingestion & preprocessing", "IMAP/SMTP · parsing · header extraction · attachment & link analysis", "am"],
    ["Data storage & persistence", "TimescaleDB · Chroma/pgvector · Neo4j · immutable forensic archive", "gr"],
    ["External integrations", "VirusTotal · AbuseIPDB · IPinfo · URLhaus · OpenPhish · Recorded Future", "mu"]
  ];
  const cascades = [
    ["Layer 1", "Signature & heuristic", ["SPF/DKIM/DMARC validation", "Known malicious domain/IP blacklists", "Pattern-based rule engine"], "88%", "bl"],
    ["Layer 2", "Classical machine learning", ["TF-IDF + Logistic Regression — 92.44%", "Random Forest", "XGBoost"], "92.4%", "cy"],
    ["Layer 3", "Deep learning", ["DistilBERT — 99.78% phishing accuracy", "BiLSTM — 98.31% hybrid", "BERT + CNN + GRU + multi-head attention"], "99.8%", "vi"],
    ["Layer 4", "LLM multi-agent reasoning", ["Text agent — content analysis", "URL agent — redirect chains", "Metadata agent — behavioural", "Adversarial agent — robustness"], "97.6%", "rd"]
  ];
  const agentRows = [
    ["Text", "Content analysis, semantic understanding", "email body → text risk"],
    ["URL", "Link analysis, redirect chain inspection", "extracted URLs → url risk"],
    ["Metadata", "Header analysis, behavioural indicators", "headers → metadata risk"],
    ["Adversarial", "Robustness testing, adversarial detection", "email + verdict → adv score"],
    ["Simplifier", "Human-readable explanations", "all outputs → plain verdict"]
  ];
  return (
    <div className="grid fu">
      <Panel title="High-level system architecture" sub="closed loop: reconnaissance → detection → training → better recognition">
        <div style={{ display: "flex", flexDirection: "column" }}>
          {layers.map((l, i) => (
            <React.Fragment key={l[0]}>
              <div className="fu" style={{ animationDelay: i * 60 + "ms", border: "1px solid " + TONE[l[2]] + "44", background: "linear-gradient(90deg," + TONE[l[2]] + "14,transparent 65%)", borderRadius: 10, padding: "11px 14px", display: "flex", gap: 12, alignItems: "center" }}>
                <span className="mono" style={{ fontSize: 9.5, color: TONE[l[2]], width: 20 }}>{pad(i + 1)}</span>
                <div style={{ flex: 1 }}>
                  <b style={{ fontSize: 12.5, color: "#e7f1f8" }}>{l[0]}</b>
                  <div style={{ fontSize: 10.8, color: "var(--mu)", marginTop: 2 }}>{l[1]}</div>
                </div>
                <span style={{ color: TONE[l[2]], display: "inline-flex" }}><Icon n="layers" s={16} /></span>
              </div>
              {i < layers.length - 1 ? <div style={{ textAlign: "center", color: "#3d5364", fontSize: 13, lineHeight: "16px" }}>▼</div> : null}
            </React.Fragment>
          ))}
        </div>
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel title="Multi-layered detection cascade" sub="each layer catches what the previous missed">
          {cascades.map((c, i) => (
            <div key={c[0]} style={{ marginBottom: 12, padding: 11, background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div><span className="mono" style={{ fontSize: 9.5, color: TONE[c[4]] }}>{c[0]}</span> <b style={{ fontSize: 12 }}>{c[1]}</b></div>
                <Badge tone={c[4]}>{c[3]} acc</Badge>
              </div>
              <ul style={{ margin: "7px 0 0", paddingLeft: 16, color: "var(--mu)", fontSize: 10.8, lineHeight: 1.7 }}>
                {c[2].map((x) => <li key={x}>{x}</li>)}
              </ul>
              {i < 3 ? <div style={{ textAlign: "center", color: "#3d5364", fontSize: 11, marginTop: 6 }}>▼ if confidence below threshold</div> : null}
            </div>
          ))}
        </Panel>

        <div className="grid">
          <Panel title="Multi-agent LLM system" sub="MultiPhishGuard paradigm" bodyStyle={{ padding: "4px 14px 14px" }}>
            <table>
              <thead><tr><Th>Agent</Th><Th>Responsibility</Th><Th>Input → Output</Th></tr></thead>
              <tbody>
                {agentRows.map((r) => (
                  <tr key={r[0]}>
                    <td><b style={{ fontSize: 11.5, color: "var(--cy)" }}>{r[0]}</b></td>
                    <td style={{ fontSize: 11 }}>{r[1]}</td>
                    <td className="mono" style={{ fontSize: 10, color: "var(--mu)" }}>{r[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ marginTop: 10, fontSize: 11, color: "var(--mu)" }}>
              Decision weights auto-tuned by <b style={{ color: "var(--vi)" }}>Proximal Policy Optimization</b>; the adversarial agent feeds novel variants back into training.
            </div>
          </Panel>
          <Panel title="Technology stack" sub="production reference implementation" bodyStyle={{ padding: "4px 14px 12px" }}>
            <div className="scroll" style={{ maxHeight: 210 }}>
              <table>
                <tbody>
                  {STACK.map((s) => (
                    <tr key={s[0]}>
                      <td style={{ width: 108, fontSize: 11, color: "var(--cy)", fontWeight: 600 }}>{s[0]}</td>
                      <td className="mono" style={{ fontSize: 10.3, color: "#9db4c4" }}>{s[1]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <Panel title="Security & compliance" sub="guardrails across the pipeline">
            {[["Data privacy", "PII masking (SSN, cards, passwords), encryption at rest/in transit, RBAC"], ["Chain of custody", "SHA-256 hashing, immutable audit log, evidence timestamping"], ["LLM guardrails", "5-layer framework: input validation, sanitisation, output verification, hallucination prevention"], ["Compliance", "GDPR · CCPA · HIPAA readiness, data residency, breach notification automation"]].map((s) => (
              <div className="mrow" key={s[0]}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, fontWeight: 600 }}>{s[0]}</div>
                  <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 2 }}>{s[1]}</div>
                </div>
              </div>
            ))}
          </Panel>
        </div>
      </div>

      <Panel title="Implementation roadmap" sub="12-month delivery plan">
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))", gap: 12 }}>
          {ROADMAP.map((p) => (
            <div key={p.phase} style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 11, padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <b style={{ fontSize: 12 }}>{p.phase}</b>
                <Badge tone="cy">{p.months}</Badge>
              </div>
              <div style={{ margin: "9px 0 11px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--mu)", marginBottom: 4 }}><span>completion</span><span className="mono">{p.progress}%</span></div>
                <Meter v={p.progress} tone={p.progress > 80 ? "gr" : (p.progress > 40 ? "cy" : "am")} />
              </div>
              {p.items.map((it) => (
                <div key={it[0]} style={{ marginBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10.8 }}><span style={{ color: "#b9cede" }}>{it[0]}</span><span className="mono" style={{ color: "var(--mu)" }}>{it[1]}%</span></div>
                  <div style={{ marginTop: 3 }}><Meter v={it[1]} tone={it[1] > 80 ? "gr" : (it[1] > 40 ? "cy" : "am")} h={4} /></div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Critical success factors" sub="architectural invariants">
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(215px,1fr))", gap: 10 }}>
          {[["Closed-loop learning", "Reconnaissance → detection → training → recognition", "cy"], ["Multi-layered defence", "No single point of failure; each layer catches what previous layers miss", "bl"], ["Explainability first", "SHAP / LIME / BDI-SHAP-X / BERTViz for analyst trust", "vi"], ["Parallel processing", "Concurrent enrichment to minimise latency", "am"], ["Adversarial training", "Self-improving defence ecosystem", "rd"], ["Forensic readiness", "Every detection is an investigation waiting to happen", "gr"]].map((x) => (
            <div key={x[0]} style={{ border: "1px solid " + TONE[x[2]] + "33", background: "linear-gradient(160deg," + TONE[x[2]] + "10,transparent)", borderRadius: 10, padding: 11 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ color: TONE[x[2]], display: "inline-flex" }}><Icon n="bolt" s={13} /></span>
                <b style={{ fontSize: 11.8 }}>{x[0]}</b>
              </div>
              <div style={{ fontSize: 10.5, color: "var(--mu)", marginTop: 5, lineHeight: 1.55 }}>{x[1]}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function Setup({ sb, toast }) {
  const [tab, setTab] = useState("keys");
  const [vals, setVals] = useState(() => {
    const all = [];
    REQUIRED_VARS.forEach((g) => g.vars.forEach((v) => all.push(v[0])));
    const o = {};
    all.forEach((k) => { o[k] = cfgGet(k); });
    return o;
  });
  const [show, setShow] = useState(false);

  const saveAll = () => {
    Object.keys(vals).forEach((k) => cfgSet(k, vals[k] || ""));
    toast("Configuration saved to localStorage (use Vercel env vars in production)");
  };
  const setVal = (k, v) => { const n = {}; Object.keys(vals).forEach((x) => { n[x] = vals[x]; }); n[k] = v; setVals(n); };
  const isSecret = (k) => /KEY|PASS|SECRET|TOKEN|DSN/.test(k);

  const V0_BLOCK = [
    "# 1. scaffold with v0",
    'npx v0 "AI email threat detection + geolocation + forensic',
    '        intelligence dashboard, dark cyber theme"',
    "",
    "# 2. or use this file directly",
    "npx create-next-app@latest sentinelgrid --ts --tailwind --app",
    "#    paste App.jsx into app/page.tsx as a client component",
    "npm i recharts @supabase/supabase-js",
    "",
    "# 3. env vars (Vercel dashboard or .env.local)",
    "NEXT_PUBLIC_SUPABASE_URL=...",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY=...",
    "",
    "# 4. ship it",
    "vercel --prod"
  ].join("\n");

  const DOCKER_BLOCK = [
    "# detection API (FastAPI + async workers)",
    "docker build -t sentinelgrid/api .",
    "docker run -p 8000:8000 \\",
    "  -e VIRUSTOTAL_API_KEY -e ABUSEIPDB_API_KEY \\",
    "  -e IPINFO_TOKEN -e OPENAI_API_KEY \\",
    "  -e DATABASE_URL -e NEO4J_URI -e REDIS_URL \\",
    "  sentinelgrid/api",
    "",
    "# local LLM for the 5-agent system",
    "ollama pull qwen2.5:14b",
    "ollama pull nomic-embed-text",
    "OLLAMA_BASE_URL=http://localhost:11434",
    "",
    "# kubernetes (scale phase)",
    "kubectl apply -f k8s/   # 100+ tenants, 99.99% HA"
  ].join("\n");

  const statusColor = sb.status === "connected" ? "#34d399" : sb.status === "error" ? "#fb7185" : "#fbbf24";
  const statusBorder = sb.status === "connected" ? "rgba(52,211,153,.4)" : sb.status === "error" ? "rgba(251,113,133,.4)" : "rgba(251,191,36,.35)";
  const statusBg = sb.status === "connected" ? "rgba(52,211,153,.07)" : sb.status === "error" ? "rgba(251,113,133,.07)" : "rgba(251,191,36,.06)";
  const flowSteps = ["IMAP/SMTP ingest", "Parse + hash", "L1→L4 detection", "Geo fusion", "IOC extract", "Supabase write", "Realtime broadcast", "This dashboard"];

  return (
    <Panel className="fu" title="Setup & credentials" sub="everything the platform needs — database, API keys, ingestion"
      right={
        <div className="tabs">
          {["keys", "database", "deploy"].map((t) => (
            <button key={t} className={"tab" + (tab === t ? " on" : "")} onClick={() => setTab(t)}>{t}</button>
          ))}
        </div>
      }>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", padding: 11, borderRadius: 10, border: "1px solid " + statusBorder, background: statusBg, marginBottom: 14 }}>
        <span style={{ display: "inline-flex" }}><Icon n={sb.status === "connected" ? "check" : (sb.status === "error" ? "x" : "warn")} s={16} c={statusColor} /></span>
        <div style={{ flex: 1 }}>
          <b style={{ fontSize: 12 }}>
            {sb.status === "connected" ? "Supabase connected" : sb.status === "error" ? "Supabase connection failed" : sb.status === "connecting" ? "Connecting…" : "Demo mode — no database attached"}
          </b>
          <div style={{ fontSize: 10.8, color: "var(--mu)", marginTop: 2 }}>{sb.msg || "All panels run on realistic local data. Add keys to persist."}</div>
        </div>
        <button className="btn sm" onClick={() => { sb.connect(); toast("Testing Supabase connection…"); }}><Icon n="refresh" s={12} />Test connection</button>
      </div>

      {tab === "keys" ? (
        <div className="grid fi">
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ background: "#0a121d", border: "1px solid rgba(34,211,238,.3)", borderRadius: 11, padding: 13 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span style={{ display: "inline-flex" }}><Icon n="db" s={15} c="#22d3ee" /></span><b style={{ fontSize: 12.5 }}>Supabase (required for persistence)</b>
              </div>
              <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 5 }}>NEXT_PUBLIC_SUPABASE_URL</div>
              <input className="inps" style={{ width: "100%", marginBottom: 9 }} placeholder="https://abcdefgh.supabase.co"
                value={vals.NEXT_PUBLIC_SUPABASE_URL || ""} onChange={(e) => setVal("NEXT_PUBLIC_SUPABASE_URL", e.target.value)} />
              <div style={{ fontSize: 10.5, color: "var(--mu)", marginBottom: 5 }}>NEXT_PUBLIC_SUPABASE_ANON_KEY</div>
              <input className="inps" style={{ width: "100%" }} type={show ? "text" : "password"} placeholder="eyJhbGciOi…"
                value={vals.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""} onChange={(e) => setVal("NEXT_PUBLIC_SUPABASE_ANON_KEY", e.target.value)} />
              <div style={{ display: "flex", gap: 8, marginTop: 11 }}>
                <button className="btn sm p" onClick={() => {
                  const u = vals.NEXT_PUBLIC_SUPABASE_URL || "";
                  const k = vals.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";
                  sb.save(u, k);
                  sb.connect(u, k);
                  toast("Credentials saved — testing connection");
                }}>Save & connect</button>
                <button className="btn sm" onClick={() => setShow(!show)}><Icon n="eye" s={12} />{show ? "Hide" : "Show"}</button>
              </div>
            </div>
            <div style={{ background: "#0a121d", border: "1px solid var(--ln)", borderRadius: 11, padding: 13 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span style={{ display: "inline-flex" }}><Icon n="cpu" s={15} c="#a78bfa" /></span><b style={{ fontSize: 12.5 }}>Quick start (3 steps)</b>
              </div>
              <ol style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, lineHeight: 1.85, color: "#b9cede" }}>
                <li>Create a Supabase project → SQL Editor → run the <b>Database Schema</b> below (16 tables + RLS + realtime).</li>
                <li>Create the private Storage bucket <span className="mono">forensic-archive</span> for immutable evidence.</li>
                <li>Add the env vars to Vercel → Project → Settings → Environment Variables, then redeploy.</li>
              </ol>
              <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--mu)" }}>
                Client-side keys are stored in <span className="mono">localStorage</span> here for demo convenience only — never ship the service-role key to the browser.
              </div>
            </div>
          </div>

          {REQUIRED_VARS.map((g) => (
            <Panel key={g.g} title={g.g} sub={g.vars.filter((v) => cfgGet(v[0])).length + " / " + g.vars.length + " configured"} bodyStyle={{ padding: "4px 14px 12px" }}>
              <table>
                <tbody>
                  {g.vars.map((v) => (
                    <tr key={v[0]}>
                      <td style={{ width: 250 }}>
                        <span className="mono" style={{ fontSize: 10.5, color: "var(--cy)" }}>{v[0]}</span>
                        {v[2] ? <span style={{ marginLeft: 6 }}><Badge tone="rd">required</Badge></span> : null}
                      </td>
                      <td style={{ fontSize: 10.8, color: "var(--mu)" }}>{v[1]}</td>
                      <td style={{ width: 250 }}>
                        <input className="inps" style={{ width: "100%", fontSize: 10.5 }}
                          type={(isSecret(v[0]) && !show) ? "password" : "text"}
                          placeholder={cfgGet(v[0]) ? "••••••••" : "not set"}
                          value={vals[v[0]] || ""} onChange={(e) => setVal(v[0], e.target.value)} />
                      </td>
                      <td style={{ width: 70 }}>{(cfgGet(v[0]) || vals[v[0]]) ? <Badge tone="gr">set</Badge> : <Badge tone="mu">empty</Badge>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          ))}

          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button className="btn" onClick={() => { Object.keys(vals).forEach((k) => cfgSet(k, "")); setVals({}); toast("All local credentials cleared"); }}>Clear all</button>
            <button className="btn p" onClick={saveAll}>Save configuration</button>
          </div>
        </div>
      ) : null}

      {tab === "database" ? (
        <div className="grid fi">
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 10 }}>
            {[["Time-series", "TimescaleDB / InfluxDB", "email metrics, detection history, performance logs", "cy"], ["Vector", "Chroma / pgvector", "embeddings, similarity search, RAG", "vi"], ["Graph", "Neo4j", "social graphs, infrastructure relationships", "rd"], ["Forensic archive", "Immutable object storage", "raw emails, evidence chain, audit logs", "am"], ["Search", "Elasticsearch", "full-text search, IOC indexing", "gr"], ["Primary", "Supabase Postgres", "cases, alerts, detections, tenants", "bl"]].map((s) => (
              <div key={s[0]} style={{ background: "#0a121d", border: "1px solid " + TONE[s[3]] + "33", borderRadius: 10, padding: 11 }}>
                <div style={{ fontSize: 9.5, letterSpacing: 1, textTransform: "uppercase", color: TONE[s[3]] }}>{s[0]}</div>
                <div style={{ fontSize: 12, fontWeight: 600, marginTop: 4 }}>{s[1]}</div>
                <div style={{ fontSize: 10.3, color: "var(--mu)", marginTop: 3 }}>{s[2]}</div>
              </div>
            ))}
          </div>
          <Panel title="Supabase schema DDL" sub="paste into Supabase → SQL Editor → Run"
            right={<button className="btn sm" onClick={() => { copy(SQL_SCHEMA); toast("SQL copied to clipboard"); }}><Icon n="copy" s={12} />Copy SQL</button>}>
            <code className="blk">{SQL_SCHEMA}</code>
          </Panel>
          <Panel title="API surface" sub="FastAPI / GraphQL / gRPC behind the gateway" bodyStyle={{ padding: "4px 14px 12px" }}>
            <table>
              <thead><tr><Th>Method</Th><Th>Endpoint</Th><Th>Purpose</Th><Th>Supabase table</Th></tr></thead>
              <tbody>
                {[["POST", "/analyze", "Submit email for analysis", "emails + detections"], ["GET", "/verdict/{id}", "Retrieve detection results", "detections"], ["POST", "/investigation", "Create new investigation", "cases"], ["GET", "/ioc/{type}/{value}", "Query IOC intelligence", "iocs"], ["GET", "/geolocation/{ip}", "Multi-signal geolocation", "geo_attributions"], ["POST", "/report/{id}", "Generate forensic report", "reports"], ["POST", "/webhook/siem", "Push alerts to SIEM/SOAR", "alerts"], ["GET", "/stream (SSE)", "Realtime alert bus", "supabase_realtime"]].map((r) => (
                  <tr key={r[1]}>
                    <td><Badge tone={r[0] === "POST" ? "cy" : "gr"}>{r[0]}</Badge></td>
                    <td className="mono" style={{ fontSize: 10.8 }}>{r[1]}</td>
                    <td style={{ fontSize: 11 }}>{r[2]}</td>
                    <td className="mono" style={{ fontSize: 10, color: "var(--mu)" }}>{r[3]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </div>
      ) : null}

      {tab === "deploy" ? (
        <div className="grid fi">
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Panel title="v0 → Vercel deployment" sub="frontend (this app)">
              <code className="blk">{V0_BLOCK}</code>
            </Panel>
            <Panel title="Backend services (separate deploy)" sub="Python detection plane">
              <code className="blk">{DOCKER_BLOCK}</code>
            </Panel>
          </div>
          <Panel title="Data-flow contract" sub="frontend ↔ Supabase ↔ detection API">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", fontSize: 11 }}>
              {flowSteps.map((s, i) => (
                <React.Fragment key={s}>
                  <span style={{ padding: "7px 11px", borderRadius: 8, border: "1px solid var(--ln2)", background: i === flowSteps.length - 1 ? "rgba(34,211,238,.12)" : "#0a121d", color: i === flowSteps.length - 1 ? "#dffaff" : "#b9cede" }}>{s}</span>
                  {i < flowSteps.length - 1 ? <span style={{ color: "#3d5364" }}>→</span> : null}
                </React.Fragment>
              ))}
            </div>
            <div style={{ marginTop: 12, fontSize: 11, color: "var(--mu)", lineHeight: 1.7 }}>
              Subscriptions: <span className="mono" style={{ color: "var(--cy)" }}>supabase.channel('alerts').on('postgres_changes', …)</span> drives the live alert console without a polling loop.
              Writes from the Analyzer go to <span className="mono">emails</span> then <span className="mono">detections</span>; evidence blobs go to the
              <span className="mono"> forensic-archive</span> bucket with SHA-256 recorded in <span className="mono">case_evidence</span>.
            </div>
          </Panel>
        </div>
      ) : null}
    </Panel>
  );
}

/* ══════════════════════════ SHELL ══════════════════════════ */
const NAV = [
  { sec: "Operations" },
  { k: "overview", l: "Analyst dashboard", i: "shield" },
  { k: "alerts", l: "Alert console", i: "bell" },
  { k: "analyzer", l: "Email analyzer", i: "mail" },
  { sec: "Intelligence" },
  { k: "geo", l: "Geolocation", i: "globe" },
  { k: "graph", l: "Social graph", i: "graph" },
  { k: "ioc", l: "IOC intel", i: "search" },
  { sec: "Forensics" },
  { k: "forensics", l: "Forensic workbench", i: "eye" },
  { k: "cases", l: "Investigations", i: "folder" },
  { k: "reports", l: "Report generator", i: "doc" },
  { sec: "Platform" },
  { k: "arch", l: "Architecture", i: "layers" },
  { k: "setup", l: "Setup & keys", i: "gear" }
];
const TITLES = {
  overview: "Analyst Dashboard", alerts: "Real-Time Alert Console", analyzer: "Email Threat Analyzer",
  geo: "Geolocation Intelligence", graph: "Social Graph Analysis", ioc: "IOC Intelligence",
  forensics: "Forensic Workbench", cases: "Investigation Management", reports: "Report Generator",
  arch: "Platform Architecture", setup: "Setup, Database & API Keys"
};

export default function App() {
  const [page, setPage] = useState("overview");
  const [alerts, setAlerts] = useState(BASE_ALERTS);
  const [cases, setCases] = useState(CASES);
  const [selAlert, setSelAlert] = useState(null);
  const [closing, setClosing] = useState(false);
  const [live, setLive] = useState(true);
  const [processed, setProcessed] = useState(184420);
  const [toasts, setToasts] = useState([]);
  const [clock, setClock] = useState(new Date().toISOString().slice(11, 19));
  const sb = useSupabase();
  const pending = useRef(null);

  const toast = useCallback((m) => {
    const id = Date.now() + Math.random();
    setToasts((t) => t.concat([{ id: id, m: m }]));
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  }, []);

  const goto = useCallback((p, alertId) => {
    setPage(p);
    if (alertId) pending.current = alertId;
  }, []);

  const closeDrawer = () => {
    setClosing(true);
    setTimeout(() => { setSelAlert(null); setClosing(false); }, 210);
  };

  useEffect(() => {
    if (pending.current && page === "alerts") {
      const found = alerts.filter((x) => x.id === pending.current)[0];
      if (found) setSelAlert(found);
      pending.current = null;
    }
  }, [page, alerts]);

  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toISOString().slice(11, 19)), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!live) return undefined;
    const t = setInterval(() => {
      setProcessed((p) => p + 7 + Math.floor(rnd(Date.now() % 997) * 22));
      if (rnd(Date.now() % 1000) > 0.45) {
        const idx = Math.floor(rnd(Date.now() % 9999) * SUBJECTS.length);
        const nid = "ALT-L" + Date.now().toString(36).toUpperCase();
        const na = mkAlert(idx, { id: nid, ts: new Date().toISOString(), status: "new", fresh: true });
        setAlerts((prev) => [na].concat(prev).slice(0, 42));
        setTimeout(() => {
          setAlerts((prev) => prev.map((x) => (x.id === nid ? Object.assign({}, x, { fresh: false }) : x)));
        }, 4200);
      }
    }, 5200);
    return () => clearInterval(t);
  }, [live]);

  useEffect(() => {
    if (sb.status !== "connected" || !sb.client) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await sb.client.from("alerts").select("*").order("created_at", { ascending: false }).limit(40);
        if (!cancelled && r.data && r.data.length) toast("Hydrated " + r.data.length + " alerts from Supabase");
      } catch (e) {}
    })();
    return () => { cancelled = true; };
  }, [sb.status, sb.client, toast]);

  const sbDot = sb.status === "connected" ? "#34d399" : (sb.status === "error" ? "#fb7185" : "#fbbf24");
  const sbLabel = sb.status === "connected" ? "Supabase live" : (sb.status === "error" ? "Supabase error" : "Demo data mode");

  return (
    <React.Fragment>
      <style>{CSS}</style>
      <div className="app">
        <aside className="side">
          <div className="logo">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
              <path d="M12 2l8 3.5v6c0 5-3.4 9.3-8 10.5-4.6-1.2-8-5.5-8-10.5v-6L12 2z" stroke="#22d3ee" strokeWidth="1.5" fill="rgba(34,211,238,.12)" />
              <circle cx="12" cy="11" r="2.6" stroke="#a78bfa" strokeWidth="1.4" />
              <path d="M12 6.5v1.9M12 13.6v1.9M7.5 11h1.9M14.6 11h1.9" stroke="#22d3ee" strokeWidth="1.2" />
            </svg>
            <div className="lbl">
              <b className="grad">SentinelGrid</b>
              <div style={{ fontSize: 9, color: "var(--mu)", letterSpacing: 0.8 }}>THREAT · GEO · FORENSICS</div>
            </div>
          </div>

          {NAV.map((item, i) => {
            if (item.sec) return <div className="navsec" key={"sec" + i}>{item.sec}</div>;
            const on = page === item.k;
            return (
              <button key={item.k} className={"navbtn" + (on ? " on" : "")} onClick={() => setPage(item.k)}>
                <span style={{ display: "inline-flex" }}><Icon n={item.i} s={15} c={on ? "#22d3ee" : "#7d93a6"} /></span>
                <span className="lbl">{item.l}</span>
                {on ? <span className="lbl" style={{ marginLeft: "auto", display: "inline-flex" }}><Icon n="che" s={12} c="#22d3ee" /></span> : null}
              </button>
            );
          })}

          <div style={{ marginTop: "auto", paddingTop: 14 }}>
            <div className="lbl" style={{ padding: "9px 10px", borderRadius: 9, border: "1px solid " + (sb.status === "connected" ? "rgba(52,211,153,.35)" : "rgba(251,191,36,.3)"), background: "#0a121d" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span className="dot" style={{ background: sbDot }} />
                <span style={{ fontSize: 10.5, color: "#b9cede" }}>{sbLabel}</span>
              </div>
              <button className="btn sm" style={{ width: "100%", marginTop: 8, justifyContent: "center" }} onClick={() => setPage("setup")}>Configure keys</button>
            </div>
          </div>
        </aside>

        <div className="main">
          <div className="top">
            <div>
              <div style={{ fontSize: 14.5, fontWeight: 650, letterSpacing: 0.2 }}>{TITLES[page]}</div>
              <div style={{ fontSize: 10, color: "var(--mu)", marginTop: 1 }}>AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform</div>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="chip" style={{ borderColor: "rgba(52,211,153,.3)" }}>
                <span className="dot" style={{ background: "#34d399", width: 6, height: 6, display: "inline-block" }} /> pipeline healthy
              </span>
              <span className="chip">{fmt(processed)} processed</span>
              <span className="chip">tenant: northwind</span>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <div className={"sw" + (live ? " on" : "")} onClick={() => { setLive(!live); toast(live ? "Live feed paused" : "Live feed resumed"); }}><i /></div>
                <span style={{ fontSize: 11, color: "var(--mu)" }}>Live</span>
              </div>
              <span className="mono" style={{ fontSize: 11, color: "var(--mu)" }}>{clock}Z</span>
            </div>
          </div>

          <div className="body">
            <div key={page}>
              {page === "overview" ? <Overview alerts={alerts} goto={goto} processed={processed} /> : null}
              {page === "alerts" ? <AlertConsole alerts={alerts} setAlerts={setAlerts} open={setSelAlert} live={live} setLive={setLive} toast={toast} /> : null}
              {page === "analyzer" ? <Analyzer sb={sb} toast={toast} setAlerts={setAlerts} /> : null}
              {page === "geo" ? <GeoPage alerts={alerts} /> : null}
              {page === "graph" ? <GraphPage toast={toast} /> : null}
              {page === "ioc" ? <IocIntel toast={toast} /> : null}
              {page === "forensics" ? <Forensics toast={toast} cases={cases} /> : null}
              {page === "cases" ? <Investigations cases={cases} setCases={setCases} toast={toast} sb={sb} /> : null}
              {page === "reports" ? <Reports cases={cases} alerts={alerts} toast={toast} /> : null}
              {page === "arch" ? <Architecture /> : null}
              {page === "setup" ? <Setup sb={sb} toast={toast} /> : null}
            </div>
          </div>
        </div>

        {selAlert ? <AlertDrawer a={selAlert} closing={closing} onClose={closeDrawer} toast={toast} setAlerts={setAlerts} goto={goto} /> : null}

        <div className="toast">
          {toasts.map((t) => (
            <div className="tt" key={t.id}>
              <span style={{ display: "inline-flex" }}><Icon n="check" s={13} c="#22d3ee" /></span>{t.m}
            </div>
          ))}
        </div>
      </div>
    </React.Fragment>
  );
}
