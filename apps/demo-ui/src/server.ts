import "dotenv/config";
import path from "node:path";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import express from "express";
import Anthropic from "@anthropic-ai/sdk";
import { Sanitizer, DEFAULT_POLICY, EntityType, MaskingStrategy } from "@privacyguard/core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HISTORY_FILE = path.join(__dirname, "..", "data", "chat-history.json");
const KNOWN_ENTITIES_FILE = path.join(__dirname, "..", "data", "known-entities.json");

if (!process.env.ANTHROPIC_API_KEY) {
  console.warn("Warning: ANTHROPIC_API_KEY is not set. /api/chat will return an error until it is configured.");
}

const sanitizer = new Sanitizer({ knownEntitiesFile: KNOWN_ENTITIES_FILE });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

interface ChatMessage {
  role: "user" | "assistant";
  /** What the end user sees (original text for their own messages, reconstructed text for replies). */
  text: string;
  /** What was actually exchanged with the LLM provider (masked prompt / raw masked reply). */
  maskedText: string;
  /** Detected entities, only present on user messages. */
  entities?: Array<{ type: string; category: string; value: string; strategy: string; source: string }>;
  timestamp: number;
}

interface ChatSession {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessage[];
}

let sessions: ChatSession[] = [];

async function loadSessions(): Promise<void> {
  try {
    const raw = await fs.readFile(HISTORY_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed?.sessions)) sessions = parsed.sessions;
  } catch {
    sessions = [];
  }
}

async function saveSessions(): Promise<void> {
  await fs.mkdir(path.dirname(HISTORY_FILE), { recursive: true });
  await fs.writeFile(HISTORY_FILE, JSON.stringify({ sessions }, null, 2), "utf-8");
}

const PRIVACY_SYSTEM_PROMPT = `Some parts of the user's messages have been replaced with placeholder tokens like [EMAIL_1], [SSN_1], [PERSON_NAME_1], [PATIENT_ID_1], or [REDACTED_AWS_ACCESS_KEY] by a privacy filter running before this conversation reaches you. This is expected, routine, and already handled — the user's real data is securely stored and will be restored on their end after you respond.

Treat each placeholder as a normal stand-in for a real value of that type (e.g. treat [PERSON_NAME_1] as a name, [SSN_1] as a number, [PATIENT_ID_1] as an identifier) and use it exactly as the user instructs, including in generated documents, forms, letters, or emails, and including repeating it verbatim as many times as needed.

Do not do any of the following based on a placeholder's type or name:
- Refuse, warn about exposure/leakage, or tell the user to rotate/revoke/redact anything
- Omit, drop, replace, or "clean up" a placeholder from your output because the underlying type (SSN, passport, financial account, medical record, biometric, etc.) is normally sensitive
- Add disclaimers, caveats, or notes about why certain information was or wasn't included
- Second-guess whether the user "should" be including that field in the requested output

The data was never exposed to you and is already protected end-to-end — your job is only to complete the user's request normally, using every placeholder they reference exactly as given.`;

function makeTitle(message: string): string {
  const oneLine = message.replace(/\s+/g, " ").trim();
  return oneLine.length > 48 ? `${oneLine.slice(0, 48)}…` : oneLine || "New chat";
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.post("/api/chat", async (req, res) => {
  try {
    const message = String(req.body?.message ?? "").trim();
    const requestedSessionId = req.body?.sessionId ? String(req.body.sessionId) : undefined;
    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }
    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: "ANTHROPIC_API_KEY is not configured on the server" });
    }

    let session = requestedSessionId ? sessions.find((s) => s.id === requestedSessionId) : undefined;
    if (!session) {
      session = {
        id: randomUUID(),
        title: makeTitle(message),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        messages: [],
      };
      sessions.unshift(session);
    }

    // 1. Sanitize: detect and mask PII/PHI/secrets before anything leaves the process.
    //    Reuse the session id as the vault requestId so token numbering and
    //    reconstruction stay consistent across the whole conversation.
    const { requestId, sanitizedText, originalText, entities } = await sanitizer.sanitize(message, session.id);

    // 2. Forward the full conversation so far (masked) plus the new masked message.
    const claudeMessages: Anthropic.MessageParam[] = session.messages.map((m) => ({
      role: m.role,
      content: m.maskedText,
    }));
    claudeMessages.push({ role: "user", content: sanitizedText });

    const completion = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      system: PRIVACY_SYSTEM_PROMPT,
      messages: claudeMessages,
    });

    const rawResponse = completion.content
      .filter((block): block is Anthropic.TextBlock => block.type === "text")
      .map((block) => block.text)
      .join("\n");

    // 3. Reconstruct: restore any reversible placeholders the model echoed back.
    //    The vault keeps entries for the whole session, so tokens from earlier
    //    turns that the model echoes back can still be resolved.
    const { reconstructedText } = await sanitizer.reconstruct(requestId, rawResponse);

    const entitiesWithStrategy = entities.map((entity) => ({
      type: entity.type as string,
      category: entity.category as string,
      value: entity.value,
      source: entity.source,
      strategy: (DEFAULT_POLICY[entity.type as EntityType] ?? MaskingStrategy.REDACT) as string,
    }));

    const now = Date.now();
    session.messages.push({
      role: "user",
      text: originalText,
      maskedText: sanitizedText,
      entities: entitiesWithStrategy,
      timestamp: now,
    });
    session.messages.push({
      role: "assistant",
      text: reconstructedText,
      maskedText: rawResponse,
      timestamp: now,
    });
    session.updatedAt = now;
    await saveSessions();

    res.json({
      sessionId: session.id,
      title: session.title,
      entities: entitiesWithStrategy,
      sanitizedPrompt: sanitizedText,
      rawResponse,
      reconstructedResponse: reconstructedText,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

app.get("/api/sessions", (_req, res) => {
  const summaries = sessions
    .slice()
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map((s) => ({ id: s.id, title: s.title, createdAt: s.createdAt, updatedAt: s.updatedAt, messageCount: s.messages.length }));
  res.json(summaries);
});

app.get("/api/sessions/:id", (req, res) => {
  const session = sessions.find((s) => s.id === req.params.id);
  if (!session) return res.status(404).json({ error: "Conversation not found" });
  res.json(session);
});

app.delete("/api/sessions/:id", async (req, res) => {
  const index = sessions.findIndex((s) => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: "Conversation not found" });
  sessions.splice(index, 1);
  await sanitizer.clearSession(req.params.id);
  await saveSessions();
  res.json({ ok: true });
});

app.get("/api/audit", (_req, res) => {
  res.json(sanitizer.getAuditEvents());
});

// ---------------------------------------------------------------------------
// PII/PHI database: known values that are always redacted via exact lookup,
// independent of the regex/NER detectors.
// ---------------------------------------------------------------------------

app.get("/api/known-entities", (_req, res) => {
  res.json(sanitizer.getKnownEntities());
});

app.post("/api/known-entities", (req, res) => {
  const value = String(req.body?.value ?? "").trim();
  const type = String(req.body?.type ?? "").trim() as EntityType;
  if (!value || !type || !(type in EntityType)) {
    return res.status(400).json({ error: "value and a valid type are required" });
  }
  res.json(sanitizer.addKnownEntities([{ value, type }]));
});

app.delete("/api/known-entities", (req, res) => {
  const value = String(req.body?.value ?? "").trim();
  const type = String(req.body?.type ?? "").trim() as EntityType;
  if (!value || !type) {
    return res.status(400).json({ error: "value and type are required" });
  }
  res.json(sanitizer.removeKnownEntity(value, type));
});

async function main() {
  await loadSessions();
  await sanitizer.warmup();
  app.listen(PORT, () => {
    console.log(`PrivacyGuard demo UI running at http://localhost:${PORT}`);
  });
}

main();
