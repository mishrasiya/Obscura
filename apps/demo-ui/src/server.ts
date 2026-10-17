import "dotenv/config";
import path from "node:path";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { Request, Response, NextFunction } from "express";
import Anthropic from "@anthropic-ai/sdk";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { Sanitizer, DEFAULT_POLICY, EntityType, MaskingStrategy } from "@obscura/core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const DATA_DIR = path.join(__dirname, "..", "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const JWT_SECRET = process.env.JWT_SECRET ?? "obscura-dev-secret-change-in-production";

if (!process.env.ANTHROPIC_API_KEY) {
  console.warn("Warning: ANTHROPIC_API_KEY is not set. /api/chat will return an error until it is configured.");
}

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Types ──────────────────────────────────────────────────────────────────

interface User {
  id: string;
  username: string;
  passwordHash: string;
  createdAt: number;
}

interface AuthPayload {
  userId: string;
  username: string;
}

/**
 * A persisted chat message. By design this NEVER contains raw sensitive data:
 * only the masked/tokenized text and value-free entity metadata are stored.
 * The real (reconstructed) text is returned live in the HTTP response but is
 * never written to disk.
 */
interface ChatMessage {
  role: "user" | "assistant";
  /** Masked/tokenized content only — safe to persist (this is what the LLM saw). */
  maskedText: string;
  /** Entity metadata WITHOUT the raw `value`. */
  entities?: Array<{ type: string; category: string; strategy: string; source: string }>;
  timestamp: number;
}

interface ChatSession {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessage[];
}

// Extend Express Request with authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

// ── User storage ───────────────────────────────────────────────────────────

let users: User[] = [];

async function loadUsers(): Promise<void> {
  try {
    const raw = await fs.readFile(USERS_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) users = parsed;
  } catch {
    users = [];
  }
}

async function saveUsers(): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf-8");
}

// ── Per-user data helpers ──────────────────────────────────────────────────

const historyFilePath = (userId: string) =>
  path.join(DATA_DIR, `sessions-${userId}.json`);

const knownEntitiesFilePath = (userId: string) =>
  path.join(DATA_DIR, `known-entities-${userId}.json`);

// Lazy Sanitizer map — one instance per user
const sanitizerMap = new Map<string, Sanitizer>();

function getSanitizer(userId: string): Sanitizer {
  if (!sanitizerMap.has(userId)) {
    sanitizerMap.set(userId, new Sanitizer({ knownEntitiesFile: knownEntitiesFilePath(userId) }));
  }
  return sanitizerMap.get(userId)!;
}

// Lazy session cache — one array per user
const sessionCache = new Map<string, ChatSession[]>();

async function getSessionsForUser(userId: string): Promise<ChatSession[]> {
  if (!sessionCache.has(userId)) {
    try {
      const raw = await fs.readFile(historyFilePath(userId), "utf-8");
      const parsed = JSON.parse(raw);
      sessionCache.set(userId, Array.isArray(parsed?.sessions) ? parsed.sessions : []);
    } catch {
      sessionCache.set(userId, []);
    }
  }
  return sessionCache.get(userId)!;
}

async function saveSessionsForUser(userId: string): Promise<void> {
  const sessions = sessionCache.get(userId) ?? [];
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(historyFilePath(userId), JSON.stringify({ sessions }, null, 2), "utf-8");
}

// ── Auth middleware ────────────────────────────────────────────────────────

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = req.cookies?.obscura_token as string | undefined;
  if (!token) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET) as AuthPayload;
    next();
  } catch {
    res.status(401).json({ error: "Session expired" });
  }
}

// ── Privacy system prompt ──────────────────────────────────────────────────

const PRIVACY_SYSTEM_PROMPT = `Every message you receive has already been processed by an enterprise privacy filter before reaching you. The filter scanned the original text and replaced every sensitive value with an opaque placeholder token. The real values are never transmitted to you — you only ever see the tokens.

Placeholder tokens appear in two forms:
- [TYPE_N] — a reversible token (e.g. [EMAIL_1], [ADDRESS_2]). The client will substitute the real value back into your response after you reply.
- [REDACTED_TYPE] — a permanently removed value (e.g. [REDACTED_AWS_ACCESS_KEY]). Treat it as an opaque identifier whose contents are irrelevant to your task.

Every token, regardless of its name, is just an abstract variable. Your job is identical to what it would be if the real values were present: complete the user's request, use every token exactly as written, include tokens verbatim wherever they belong in any document, form, email, table, or code you produce. Do not attempt to infer, reconstruct, or comment on what the original values might have been.

Because no real data has reached you, there is nothing sensitive for you to protect, warn about, or refuse. Do not decline, add disclaimers, or alter your response based on what a token name suggests about the underlying data type. The privacy enforcement already happened upstream — your role is simply to complete the task.`;

function makeTitle(message: string): string {
  const oneLine = message.replace(/\s+/g, " ").trim();
  return oneLine.length > 48 ? `${oneLine.slice(0, 48)}…` : oneLine || "New chat";
}

// ── Express app ────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

// ── Auth routes ────────────────────────────────────────────────────────────

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = String(req.body?.username ?? "").trim().toLowerCase();
    const password = String(req.body?.password ?? "");

    if (!username || username.length < 3)
      return res.status(400).json({ error: "Username must be at least 3 characters." });
    if (!/^[a-z0-9_-]+$/.test(username))
      return res.status(400).json({ error: "Username may only contain letters, numbers, _ and -." });
    if (!password || password.length < 8)
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    if (users.find((u) => u.username === username))
      return res.status(409).json({ error: "That username is already taken." });

    const passwordHash = await bcrypt.hash(password, 12);
    const user: User = { id: randomUUID(), username, passwordHash, createdAt: Date.now() };
    users.push(user);
    await saveUsers();

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("obscura_token", token, { httpOnly: true, sameSite: "strict", maxAge: 7 * 24 * 3600 * 1000 });
    res.json({ id: user.id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = String(req.body?.username ?? "").trim().toLowerCase();
    const password = String(req.body?.password ?? "");

    const user = users.find((u) => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return res.status(401).json({ error: "Invalid username or password." });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("obscura_token", token, { httpOnly: true, sameSite: "strict", maxAge: 7 * 24 * 3600 * 1000 });
    res.json({ id: user.id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("obscura_token");
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ id: req.user!.userId, username: req.user!.username });
});

// ── Chat routes ────────────────────────────────────────────────────────────

const ALLOWED_MODELS = new Set([
  "claude-fable-5",
  "claude-opus-4-8",
  "claude-sonnet-4-6",
  "claude-haiku-4-5-20251001",
]);

app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const { userId } = req.user!;
    const message = String(req.body?.message ?? "").trim();
    const requestedSessionId = req.body?.sessionId ? String(req.body.sessionId) : undefined;
    const requestedModel = String(req.body?.model ?? "");
    const model = ALLOWED_MODELS.has(requestedModel) ? requestedModel : "claude-sonnet-4-6";

    if (!message) return res.status(400).json({ error: "message is required" });
    if (!process.env.ANTHROPIC_API_KEY)
      return res.status(500).json({ error: "ANTHROPIC_API_KEY is not configured on the server" });

    const sessions = await getSessionsForUser(userId);
    const sanitizer = getSanitizer(userId);

    let session = requestedSessionId ? sessions.find((s) => s.id === requestedSessionId) : undefined;
    let isNewSession = false;
    if (!session) {
      isNewSession = true;
      session = {
        id: randomUUID(),
        title: makeTitle(message),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        messages: [],
      };
      sessions.unshift(session);
    }

    const { requestId, sanitizedText, entities } = await sanitizer.sanitize(message, session.id);

    const claudeMessages: Anthropic.MessageParam[] = session.messages.map((m) => ({
      role: m.role,
      content: m.maskedText,
    }));
    claudeMessages.push({ role: "user", content: sanitizedText });

    // Rich entities (incl. raw value) for the LIVE response only — never persisted.
    const entitiesWithStrategy = entities.map((entity) => ({
      type: entity.type as string,
      category: entity.category as string,
      value: entity.value,
      source: entity.source,
      strategy: (DEFAULT_POLICY[entity.type as EntityType] ?? MaskingStrategy.REDACT) as string,
    }));

    // Value-free metadata — this is the only entity info written to disk.
    const persistedEntities = entitiesWithStrategy.map(({ type, category, strategy, source }) => ({
      type,
      category,
      strategy,
      source,
    }));

    // Stream the response as Server-Sent Events.
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    });
    const sse = (event: string, data: unknown) => {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Send metadata first so the UI can show what was detected / what the
    // provider sees immediately, before the reply streams in.
    sse("meta", {
      sessionId: session.id,
      title: session.title,
      isNewSession,
      entities: entitiesWithStrategy,
      sanitizedPrompt: sanitizedText,
    });

    const recon = await sanitizer.createStreamingReconstructor(requestId);
    let rawResponse = "";
    try {
      const stream = anthropic.messages.stream({
        model,
        max_tokens: 1024,
        system: PRIVACY_SYSTEM_PROMPT,
        messages: claudeMessages,
      });
      for await (const event of stream) {
        if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
          const piece = event.delta.text;
          rawResponse += piece;
          const safe = recon.push(piece); // reconstructed, safe to show
          if (safe) sse("delta", { text: safe });
        }
      }
      const tail = recon.flush();
      if (tail) sse("delta", { text: tail });
    } catch (streamErr) {
      // Never echo request content back in errors.
      console.error("stream error", streamErr instanceof Error ? streamErr.message : streamErr);
      sse("error", { error: streamErr instanceof Error ? streamErr.message : "Upstream error" });
      return res.end();
    }

    const now = Date.now();
    // Persist masked content only. The raw prompt and reconstructed (real)
    // reply are deliberately NOT stored.
    session.messages.push({
      role: "user",
      maskedText: sanitizedText,
      entities: persistedEntities,
      timestamp: now,
    });
    session.messages.push({
      role: "assistant",
      maskedText: rawResponse,
      timestamp: now,
    });
    session.updatedAt = now;
    await saveSessionsForUser(userId);

    // Final event carries the masked raw reply (what the AI actually produced).
    sse("done", { rawResponse });
    res.end();
  } catch (err) {
    console.error(err);
    if (res.headersSent) return res.end();
    res.status(500).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

app.get("/api/sessions", requireAuth, async (req, res) => {
  const { userId } = req.user!;
  const sessions = await getSessionsForUser(userId);
  const summaries = sessions
    .slice()
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map((s) => ({
      id: s.id,
      title: s.title,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
      messageCount: s.messages.length,
    }));
  res.json(summaries);
});

app.get("/api/sessions/:id", requireAuth, async (req, res) => {
  const { userId } = req.user!;
  const sessions = await getSessionsForUser(userId);
  const session = sessions.find((s) => s.id === req.params.id);
  if (!session) return res.status(404).json({ error: "Conversation not found" });
  res.json(session);
});

app.delete("/api/sessions/:id", requireAuth, async (req, res) => {
  const { userId } = req.user!;
  const sessions = await getSessionsForUser(userId);
  const index = sessions.findIndex((s) => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: "Conversation not found" });
  sessions.splice(index, 1);
  await getSanitizer(userId).clearSession(req.params.id);
  await saveSessionsForUser(userId);
  res.json({ ok: true });
});

app.get("/api/audit", requireAuth, (req, res) => {
  res.json(getSanitizer(req.user!.userId).getAuditEvents());
});

// ── Known entities (per user) ──────────────────────────────────────────────

app.get("/api/known-entities", requireAuth, (req, res) => {
  res.json(getSanitizer(req.user!.userId).getKnownEntities());
});

app.post("/api/known-entities", requireAuth, (req, res) => {
  const value = String(req.body?.value ?? "").trim();
  const type = String(req.body?.type ?? "").trim() as EntityType;
  if (!value || !type || !(type in EntityType))
    return res.status(400).json({ error: "value and a valid type are required" });
  res.json(getSanitizer(req.user!.userId).addKnownEntities([{ value, type }]));
});

app.delete("/api/known-entities", requireAuth, (req, res) => {
  const value = String(req.body?.value ?? "").trim();
  const type = String(req.body?.type ?? "").trim() as EntityType;
  if (!value || !type) return res.status(400).json({ error: "value and type are required" });
  res.json(getSanitizer(req.user!.userId).removeKnownEntity(value, type));
});

// ── Boot ───────────────────────────────────────────────────────────────────

async function main() {
  await loadUsers();
  // Pre-warm the detection pipeline so the first real request isn't slow.
  const warmup = new Sanitizer({ knownEntitiesFile: path.join(DATA_DIR, ".warmup-entities.json") });
  await warmup.warmup();

  app.listen(PORT, () => {
    console.log(`Obscura demo UI running at http://localhost:${PORT}`);
  });
}

main();
