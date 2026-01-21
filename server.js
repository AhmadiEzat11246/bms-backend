import express from "express";
import bodyParser from "body-parser";
import fs from "fs";
import cors from "cors";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const HMAC_SECRET_KEY = process.env.HMAC_SECRET_KEY;

app.use(cors({
  origin: [
    "https://ahmadiezat11246.github.io",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-BMS-Signature"]
}));

// Optional but recommended: limit body size to avoid abuse/log flooding
app.use(bodyParser.json({ limit: "50kb" }));

function enc(v) {
  return encodeURIComponent(v ?? "");
}

/**
 * V2 canonical string MUST match the HMI exactly:
 * MachineName, MachineID, ErrorCode, ErrorText, iat, exp, nonce, deviceId, kid
 * (same order, URL-encoding)
 */
function buildCanonicalStringV2(p) {
  return (
    "MachineName=" + enc(p.MachineName) +
    "&MachineID=" + enc(p.MachineID) +
    "&ErrorCode=" + enc(p.ErrorCode) +
    "&ErrorText=" + enc(p.ErrorText) +
    "&iat=" + enc(p.iat) +
    "&exp=" + enc(p.exp) +
    "&nonce=" + enc(p.nonce) +
    "&deviceId=" + enc(p.deviceId) +
    "&kid=" + enc(p.kid)
  );
}

function hmacSha256Hex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

function safeCompareHex(a, b) {
  const aNorm = (a || "").toLowerCase();
  const bNorm = (b || "").toLowerCase();

  if (aNorm.length !== bNorm.length || aNorm.length === 0) return false;
  if (!/^[0-9a-f]+$/.test(aNorm) || !/^[0-9a-f]+$/.test(bNorm)) return false;

  const bufA = Buffer.from(aNorm, "hex");
  const bufB = Buffer.from(bNorm, "hex");
  if (bufA.length !== bufB.length) return false;

  return crypto.timingSafeEqual(bufA, bufB);
}

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function randomNonceHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

/**
 * Server-side issuing endpoint (optional in your offline-HMI scenario).
 * You can keep it for testing/demo, but your real flow is HMI-side signing.
 */
app.post("/issue-link", (req, res) => {
  try {
    if (!HMAC_SECRET_KEY) {
      return res.status(500).json({ message: "Server misconfigured: missing HMAC_SECRET_KEY" });
    }

    const body = req.body || {};

    const MachineName = body.MachineName ?? "";
    const MachineID   = body.MachineID ?? "";
    const ErrorCode   = body.ErrorCode ?? "";
    const ErrorText   = body.ErrorText ?? "";

    const deviceId = body.deviceId ?? "HMI-UNKNOWN";
    const kid      = String(body.kid ?? "1");

    const iat = nowUnix();
    const exp = iat + 60;
    const nonce = randomNonceHex(16);

    const payload = {
      MachineName,
      MachineID,
      ErrorCode,
      ErrorText,
      iat: String(iat),
      exp: String(exp),
      nonce,
      deviceId,
      kid
    };

    const canonical = buildCanonicalStringV2(payload);
    const sig = hmacSha256Hex(HMAC_SECRET_KEY, canonical);

    const baseUrl =
      process.env.FRONTEND_BASE_URL ||
      "https://ahmadiezat11246.github.io/QR/ContactPage.html";

    const signedUrl =
      baseUrl +
      "?MachineName=" + enc(MachineName) +
      "&MachineID=" + enc(MachineID) +
      "&ErrorCode=" + enc(ErrorCode) +
      "&ErrorText=" + enc(ErrorText) +
      "&iat=" + enc(iat) +
      "&exp=" + enc(exp) +
      "&nonce=" + enc(nonce) +
      "&deviceId=" + enc(deviceId) +
      "&kid=" + enc(kid) +
      "&sig=" + enc(sig);

    return res.status(200).json({ ok: true, signedUrl, payload });

  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});


// Optional: in-memory replay cache (prototype). Add later if you want replay protection.
// const seenNonces = new Map(); // key: deviceId|nonce -> expUnix

app.post("/log", (req, res) => {
  try {
    if (!HMAC_SECRET_KEY) {
      return res.status(500).json({ message: "Server misconfigured: missing HMAC_SECRET_KEY" });
    }

    const data = req.body || {};
    const machinePart = data.machine ? data.machine : data;

    // Accept signature from body (sig) or legacy header
    const receivedSig =
      ((machinePart.sig || data.sig || req.get("X-BMS-Signature")) || "").toLowerCase();

    if (!receivedSig) {
      return res.status(400).json({ message: "Missing signature (sig in body or X-BMS-Signature header)" });
    }

    // Require the V2 fields (scope removed)
    const required = ["MachineName","MachineID","ErrorCode","ErrorText","iat","exp","nonce","deviceId","kid"];
    for (const k of required) {
      const val = machinePart[k];
      if (val === undefined || val === null || String(val).length === 0) {
        return res.status(400).json({ message: `Missing required field: ${k}` });
      }
    }

    // Enforce expiry
    const now = nowUnix();
    const exp = Number(machinePart.exp);
    if (!Number.isFinite(exp)) {
      return res.status(400).json({ message: "Invalid exp (must be unix seconds)" });
    }
    if (now > exp) {
      return res.status(401).json({ message: "Token expired" });
    }

    // Verify signature over canonical V2 (scope removed)
    const canonical = buildCanonicalStringV2({
      MachineName: String(machinePart.MachineName),
      MachineID: String(machinePart.MachineID),
      ErrorCode: String(machinePart.ErrorCode),
      ErrorText: String(machinePart.ErrorText),
      iat: String(machinePart.iat),
      exp: String(machinePart.exp),
      nonce: String(machinePart.nonce),
      deviceId: String(machinePart.deviceId),
      kid: String(machinePart.kid)
    });

    const expectedSig = hmacSha256Hex(HMAC_SECRET_KEY, canonical);

    if (!safeCompareHex(receivedSig, expectedSig)) {
      return res.status(401).json({ message: "Invalid signature (tampered or wrong secret)" });
    }

    // If you want replay protection later, check/store nonce here.

    const timestamp = new Date().toISOString();
    const logEntry = { ...data, timestamp, verified: true };

    fs.appendFileSync("machine_logs.json", JSON.stringify(logEntry) + "\n");

    return res.status(200).json({ message: "Data logged successfully", verified: true });

  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/logs", (req, res) => {
  try {
    const raw = fs.existsSync("machine_logs.json") ? fs.readFileSync("machine_logs.json", "utf-8") : "";
    const trimmed = raw.trim();
    const logs = trimmed ? trimmed.split("\n").map(line => JSON.parse(line)) : [];
    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: "Error reading log file", error: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
