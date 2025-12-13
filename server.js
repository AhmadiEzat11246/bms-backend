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

app.use(bodyParser.json());

function enc(v) {
  return encodeURIComponent(v ?? "");
}

function buildCanonicalString(body) {
  return (
    "MachineName=" + enc(body.MachineName) +
    "&MachineID=" + enc(body.MachineID) +
    "&ErrorCode=" + enc(body.ErrorCode) +
    "&ErrorText=" + enc(body.ErrorText)
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

app.post("/log", (req, res) => {
  try {
    if (!HMAC_SECRET_KEY) {
      return res.status(500).json({ message: "Server misconfigured: missing HMAC_SECRET_KEY" });
    }

    const data = req.body;

    // Signature from header, not from JSON
    const receivedSig = (req.get("X-BMS-Signature") || "").toLowerCase();
    if (!receivedSig) {
      return res.status(400).json({ message: "Missing signature header" });
    }

    // Build canonical string from machine object (if present) otherwise from body
    const machinePart = data.machine ? data.machine : data;
    const canonical = buildCanonicalString(machinePart);

    const expectedSig = hmacSha256Hex(HMAC_SECRET_KEY, canonical);

    if (!safeCompareHex(receivedSig, expectedSig)) {
      return res.status(401).json({ message: "Invalid signature (tampered or wrong secret)" });
    }

    const timestamp = new Date().toISOString();
    const logEntry = { ...data, timestamp, verified: true };

    fs.appendFileSync("machine_logs.json", JSON.stringify(logEntry) + "\n");

    console.log("✅ Verified & logged data:", logEntry);
    res.status(200).json({ message: "Data logged successfully", verified: true });

  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
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
