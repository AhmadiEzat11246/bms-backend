import express from "express";
import bodyParser from "body-parser";
import fs from "fs";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: [
    "https://ahmadiezat11246.github.io", // allow your GitHub Pages
    "http://localhost:3000"              // allow local testing too
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));
app.use(bodyParser.json());

// POST endpoint for machine logs
app.post("/log", (req, res) => {
  const data = req.body;
  const timestamp = new Date().toISOString();
  const logEntry = { ...data, timestamp };

  fs.appendFileSync("machine_logs.json", JSON.stringify(logEntry) + "\n");

  console.log("✅ Received data:", logEntry);
  res.status(200).json({ message: "Data logged successfully" });
});

// ✅ GET endpoint to fetch all logs
app.get("/logs", (req, res) => {
  try {
    const logs = fs.readFileSync("machine_logs.json", "utf-8")
      .trim()
      .split("\n")
      .map(line => JSON.parse(line));

    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: "Error reading log file", error: err.message });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
