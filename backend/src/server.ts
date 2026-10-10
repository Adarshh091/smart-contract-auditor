// ─── Backend API Server ────────────────────────────────────────────────────────
//
// Express server that:
//   1. Proxies Gemini API requests (GEMINI_API_KEY stays server-side only).
//   2. Exposes analysis endpoints for CFG, Taint, and PoC engines.
//
// Environment variables (set in backend/.env):
//   GEMINI_API_KEY  - Required for /api/semantic-analyze
//   PORT            - Optional, defaults to 3001

import "dotenv/config";
import express from "express";
import cors from "cors";
import { semanticAnalyzeRoute } from "./routes/semantic-analyze.js";

const app = express();
const PORT = process.env["PORT"] ? parseInt(process.env["PORT"], 10) : 3001;

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors({
  origin: [
    "http://localhost:5173",   // Vite dev server
    "http://localhost:4173",   // Vite preview
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));

app.use(express.json({ limit: "2mb" }));

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    geminiConfigured: !!(process.env["GEMINI_API_KEY"]),
  });
});

// Gemini semantic analysis proxy
app.post("/api/semantic-analyze", semanticAnalyzeRoute);

// ─── Server Start ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[backend] Server running on http://localhost:${PORT}`);
  if (!process.env["GEMINI_API_KEY"]) {
    console.warn("[backend] WARNING: GEMINI_API_KEY is not set in backend/.env");
    console.warn("[backend]   Semantic analysis endpoint will return errors.");
  } else {
    console.log("[backend] GEMINI_API_KEY is configured ✓");
  }
});

export default app;
