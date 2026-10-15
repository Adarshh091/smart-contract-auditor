// ─── Gemini Semantic Analysis Proxy Route ────────────────────────────────────
//
// POST /api/semantic-analyze
//
// Request body (sent by frontend/src/utils/semantic-analyzer.ts):
//   { prompt: string; contractText: string }
//
// Response on success:
//   { ok: true; text: string; model: string }
//
// Response on error:
//   { ok: false; error: string; errorType: string; detail?: string }
//
// The GEMINI_API_KEY environment variable is ONLY read here on the server.
// It is never forwarded to or exposed in the frontend bundle.

import type { Request, Response } from "express";

const GEMINI_MODEL = process.env["GEMINI_MODEL"] || "gemini-3.6-flash";
const GEMINI_API_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

const MODEL_NAME = process.env["GEMINI_MODEL"] ? process.env["GEMINI_MODEL"] : "Gemini 3.6 Flash";

export async function semanticAnalyzeRoute(req: Request, res: Response): Promise<void> {
  const apiKey = process.env["GEMINI_API_KEY"];

  if (!apiKey || apiKey.trim() === "" || apiKey === "your_gemini_api_key_here") {
    res.status(401).json({
      ok: false,
      error: "GEMINI_API_KEY is not configured on the server.",
      errorType: "missing-key",
      detail: "Set GEMINI_API_KEY in backend/.env and restart the server.",
    });
    return;
  }

  const { prompt, contractText } = req.body as { prompt?: string; contractText?: string };

  if (!prompt || typeof prompt !== "string") {
    res.status(400).json({
      ok: false,
      error: "Missing required field: prompt",
      errorType: "invalid-response",
    });
    return;
  }

  // Log only for dev/debug; never log the API key itself
  if (process.env["NODE_ENV"] !== "production") {
    const previewLen = 120;
    console.log(
      `[semantic-analyze] Request received. Contract text length: ${(contractText ?? "").length} chars.`
    );
    console.log(`[semantic-analyze] Prompt preview: ${prompt.slice(0, previewLen)}...`);
  }

  try {
    const geminiResponse = await fetch(`${GEMINI_API_URL}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [
          {
            parts: [{ text: prompt }],
          },
        ],
        generationConfig: {
          temperature: 0.1,
          topK: 1,
          topP: 1,
          maxOutputTokens: 1024,
        },
        safetySettings: [
          { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
        ],
      }),
    });

    if (!geminiResponse.ok) {
      const errText = await geminiResponse.text().catch(() => "");
      console.error(`[semantic-analyze] Gemini API error HTTP ${geminiResponse.status}: ${errText}`);
      res.status(502).json({
        ok: false,
        error: `Gemini API returned HTTP ${geminiResponse.status}`,
        errorType: "connection",
        detail: errText.slice(0, 400),
      });
      return;
    }

    const data = await geminiResponse.json() as {
      candidates?: Array<{
        content?: { parts?: Array<{ text?: string }> };
        finishReason?: string;
      }>;
      error?: { message?: string };
    };

    if (data.error) {
      res.status(502).json({
        ok: false,
        error: data.error.message || "Gemini API error",
        errorType: "connection",
      });
      return;
    }

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text ?? "";

    if (!text) {
      res.status(502).json({
        ok: false,
        error: "Gemini returned an empty response.",
        errorType: "invalid-response",
        detail: JSON.stringify(data).slice(0, 400),
      });
      return;
    }

    res.json({ ok: true, text, model: MODEL_NAME });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[semantic-analyze] Unexpected error: ${msg}`);
    res.status(500).json({
      ok: false,
      error: `Internal server error: ${msg}`,
      errorType: "connection",
    });
  }
}
