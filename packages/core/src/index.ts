import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  AuditEvent,
  AuditSink,
  DetectedEntity,
  ENTITY_CATEGORY,
  EntityType,
  KnownEntity,
  ReconstructResult,
  SanitizeResult,
  SanitizerConfig,
  VaultStore,
} from "./types.js";
import { detectWithRegex } from "./detectors/regex/regexDetector.js";
import { detectWithNer, warmupNer } from "./detectors/ner/nerDetector.js";
import { detectWithDictionary } from "./detectors/dictionary/dictionaryDetector.js";
import { detectObfuscated } from "./detectors/obfuscation/obfuscationDetector.js";
import { mergeEntities } from "./merge.js";
import { PolicyEngine } from "./policy/policyEngine.js";
import { applyMasking } from "./masking/masker.js";
import { MemoryVaultStore } from "./vault/memoryVaultStore.js";
import { InMemoryAuditSink, buildAuditEvent } from "./audit/auditLogger.js";
import { reconstruct as reconstructResponse } from "./reconstruction/reconstructor.js";
import {
  createStreamingReconstructor as createStreamingReconstructorImpl,
  StreamingReconstructor,
} from "./reconstruction/streamingReconstructor.js";

export * from "./types.js";
export { DEFAULT_POLICY, PolicyEngine } from "./policy/policyEngine.js";
export { MemoryVaultStore } from "./vault/memoryVaultStore.js";
export { InMemoryAuditSink } from "./audit/auditLogger.js";
export { detectWithRegex } from "./detectors/regex/regexDetector.js";
export { detectWithNer, warmupNer } from "./detectors/ner/nerDetector.js";
export { detectWithDictionary } from "./detectors/dictionary/dictionaryDetector.js";
export { detectObfuscated } from "./detectors/obfuscation/obfuscationDetector.js";
export { createStreamingReconstructor } from "./reconstruction/streamingReconstructor.js";
export type { StreamingReconstructor } from "./reconstruction/streamingReconstructor.js";

const DEFAULT_VAULT_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Privacy-first sanitization engine. Sits between an application and any
 * third-party LLM provider:
 *
 *   1. `sanitize(text)` - detects PII/PHI/secrets, masks them according to
 *      policy, and returns text safe to send to an external LLM.
 *   2. (application forwards the sanitized text to GPT/Claude/Gemini/etc.)
 *   3. `reconstruct(requestId, responseText)` - restores any reversible
 *      placeholders in the model's response so the end user sees their
 *      original data.
 *
 * All detection and tokenization happens locally; the vault holding the
 * mapping between placeholders and real values never leaves this process
 * (unless a custom `VaultStore` is configured to do so deliberately).
 */
export class Sanitizer {
  private readonly policy: PolicyEngine;
  private readonly vault: VaultStore;
  private readonly auditSink: AuditSink;
  private readonly enableNer: boolean;
  private readonly vaultTtlMs: number;
  private readonly customRules;
  private readonly knownEntitiesFile?: string;
  private knownEntities: KnownEntity[];

  constructor(config: SanitizerConfig = {}) {
    this.customRules = config.customRules ?? [];
    this.policy = new PolicyEngine(config.policy, this.customRules);
    this.vaultTtlMs = config.vaultTtlMs ?? DEFAULT_VAULT_TTL_MS;
    this.vault =
      config.vaultStore ??
      new MemoryVaultStore({ encryptionKey: config.encryptionKey, ttlMs: this.vaultTtlMs });
    this.auditSink = config.auditSink ?? new InMemoryAuditSink();
    this.enableNer = config.enableNer ?? true;

    this.knownEntitiesFile = config.knownEntitiesFile;
    this.knownEntities = [...(config.knownEntities ?? []), ...this.loadKnownEntitiesFile()];
  }

  private loadKnownEntitiesFile(): KnownEntity[] {
    if (!this.knownEntitiesFile) return [];
    try {
      const raw = fs.readFileSync(this.knownEntitiesFile, "utf-8");
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  private saveKnownEntitiesFile(): void {
    if (!this.knownEntitiesFile) return;
    fs.mkdirSync(path.dirname(this.knownEntitiesFile), { recursive: true });
    fs.writeFileSync(this.knownEntitiesFile, JSON.stringify(this.knownEntities, null, 2), "utf-8");
  }

  /** Returns the current PII/PHI lookup database (known values matched verbatim, no AI/regex guessing). */
  getKnownEntities(): KnownEntity[] {
    return [...this.knownEntities];
  }

  /**
   * Adds entries to the known-value database (deduplicated by value+type,
   * case-insensitive). Persists to `knownEntitiesFile` if configured.
   */
  addKnownEntities(entries: KnownEntity[]): KnownEntity[] {
    for (const entry of entries) {
      const value = entry.value?.trim();
      if (!value) continue;
      const exists = this.knownEntities.some(
        (e) => e.type === entry.type && e.value.toLowerCase() === value.toLowerCase()
      );
      if (!exists) this.knownEntities.push({ value, type: entry.type });
    }
    this.saveKnownEntitiesFile();
    return this.getKnownEntities();
  }

  /** Removes a single entry (case-insensitive value match) from the known-value database. */
  removeKnownEntity(value: string, type: KnownEntity["type"]): KnownEntity[] {
    this.knownEntities = this.knownEntities.filter(
      (e) => !(e.type === type && e.value.toLowerCase() === value.toLowerCase())
    );
    this.saveKnownEntitiesFile();
    return this.getKnownEntities();
  }

  /** Pre-loads the local NER model so the first `sanitize()` call isn't slowed by model loading. */
  async warmup(): Promise<void> {
    if (this.enableNer) await warmupNer();
  }

  /**
   * Self-consistency pass: NER may tag a name/org/location in one position
   * but miss the same value elsewhere (e.g. a proxy name under "Prepared by"),
   * or miss a related name entirely. Two complementary sweeps fill those gaps,
   * then we re-merge. Existing (higher-priority) spans win on overlap, so this
   * only ever adds coverage.
   *
   *  1. Verbatim sweep: every detected name/org/location is treated as a known
   *     value and all its other occurrences are masked.
   *  2. Surname sweep: for multi-token person names we learn the surname and
   *     mask "<FirstName...> Surname" (and the bare surname) anywhere it
   *     appears — catching e.g. "Marcus Pendelton" from having seen "Arthur
   *     Pendelton", even if NER never tagged Marcus.
   */
  private propagateNamedEntities(text: string, entities: DetectedEntity[]): DetectedEntity[] {
    const PROPAGATE = new Set<EntityType>([
      EntityType.PERSON_NAME,
      EntityType.ORGANIZATION,
      EntityType.LOCATION,
    ]);

    const seen = new Set<string>();
    const knownFromDetections: KnownEntity[] = [];
    const surnames = new Set<string>();
    for (const e of entities) {
      if (!PROPAGATE.has(e.type as EntityType)) continue;
      const value = e.value.trim();
      // Skip trivially short values to avoid masking common words.
      if (value.length < 3) continue;
      const key = `${e.type}:${value.toLowerCase()}`;
      if (!seen.has(key)) {
        seen.add(key);
        knownFromDetections.push({ value, type: e.type as KnownEntity["type"] });
      }
      if (e.type === EntityType.PERSON_NAME) {
        // Split on spaces AND HL7/JSON delimiters (^ , ") so e.g.
        // "PENDELTON^ARTHUR^J" yields PENDELTON / ARTHUR, and collect each
        // substantial part as a name token to sweep across other formats.
        const tokens = value.split(/[\s^,"]+/).filter((t) => t.length >= 4 && /^[A-Za-z'’.-]+$/.test(t));
        for (const t of tokens) surnames.add(t);
      }
    }

    const extraOccurrences =
      knownFromDetections.length > 0 ? detectWithDictionary(text, knownFromDetections) : [];

    const nameHits: DetectedEntity[] = [];
    for (const surname of surnames) {
      // Match the surname case-insensitively (so an upper-case HL7 token
      // "PENDELTON" also hits the mixed-case FHIR "Pendelton") via a per-char
      // class, while keeping the optional leading given-name tokens strictly
      // upper/title-case - otherwise (with a global /i) the leading group would
      // swallow lower-case prose like "by" in "by Marcus Pendelton".
      const ciSurname = surname
        .split("")
        .map((c) => (/[a-z]/i.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))
        .join("");
      const re = new RegExp(`\\b(?:[A-Z][A-Za-z'’.-]+[\\s^]+){0,2}${ciSurname}\\b`, "g");
      for (const m of text.matchAll(re)) {
        if (m.index === undefined) continue;
        // Skip lower-case prose usages (e.g. the word "will"); real names in
        // these records are upper- or title-cased.
        if (!/[A-Z]/.test(m[0][0])) continue;
        nameHits.push({
          type: EntityType.PERSON_NAME,
          category: ENTITY_CATEGORY[EntityType.PERSON_NAME],
          value: m[0],
          start: m.index,
          end: m.index + m[0].length,
          confidence: 1,
          source: "dictionary",
        });
      }
    }

    if (extraOccurrences.length === 0 && nameHits.length === 0) return entities;
    return mergeEntities(entities, extraOccurrences, nameHits);
  }

  /**
   * Detects and masks sensitive entities in `text`. Returns the sanitized
   * text (safe to forward to an external LLM) along with the entities found.
   *
   * @param text the raw prompt/message content
   * @param requestId optional correlation id; generated if omitted. Use the
   *   same id when calling `reconstruct()` for this exchange.
   */
  async sanitize(text: string, requestId: string = randomUUID()): Promise<SanitizeResult> {
    const dictionaryEntities = detectWithDictionary(text, this.knownEntities);
    const regexEntities = detectWithRegex(text, this.customRules);
    const obfuscatedEntities = detectObfuscated(text);
    const nerEntities = this.enableNer ? await detectWithNer(text) : [];
    const merged = mergeEntities(dictionaryEntities, regexEntities, obfuscatedEntities, nerEntities);
    const entities = this.propagateNamedEntities(text, merged);

    // If this requestId already has vault entries (e.g. earlier turns in the
    // same conversation), continue token numbering from where they left off
    // so tokens stay unique and resolvable across the whole session.
    const existingRecords = await this.vault.getAll(requestId);
    const initialTokenCounters = new Map<string, number>();
    for (const record of existingRecords) {
      const match = /^\[(.+)_(\d+)\]$/.exec(record.token);
      if (!match) continue;
      const [, type, numStr] = match;
      const num = Number(numStr);
      if ((initialTokenCounters.get(type) ?? 0) < num) {
        initialTokenCounters.set(type, num);
      }
    }

    const { sanitizedText, pendingVaultEntries } = applyMasking(text, entities, this.policy, initialTokenCounters);

    const now = Date.now();
    for (const entry of pendingVaultEntries) {
      await this.vault.set({
        token: entry.token,
        value: entry.value,
        type: entry.type,
        requestId,
        createdAt: now,
        expiresAt: now + this.vaultTtlMs,
      });
    }

    this.auditSink.record(buildAuditEvent(requestId, "sanitize", entities));

    return { requestId, sanitizedText, originalText: text, entities };
  }

  /**
   * Sanitizes multiple related pieces of text (e.g. every message in a chat
   * conversation) as a single unit so that entity numbering (`[EMAIL_1]`,
   * `[EMAIL_2]`, ...) and vault tokens stay consistent and collision-free
   * across the whole exchange, while still returning per-text results.
   *
   * @param texts ordered list of texts (e.g. message contents)
   * @param requestId optional correlation id; generated if omitted
   */
  async sanitizeBatch(
    texts: string[],
    requestId: string = randomUUID()
  ): Promise<{ requestId: string; sanitizedTexts: string[]; entities: SanitizeResult["entities"] }> {
    const separator = " OBSCURA_BOUNDARY ";
    const combined = texts.join(separator);
    const result = await this.sanitize(combined, requestId);
    const sanitizedTexts = result.sanitizedText.split(separator);
    return { requestId, sanitizedTexts, entities: result.entities };
  }

  /**
   * Restores reversible placeholders (e.g. `[EMAIL_1]`) in a provider
   * response with the original values captured during `sanitize()`.
   *
   * @param requestId the id returned from the corresponding `sanitize()` call
   * @param responseText the raw text returned by the LLM provider
   */
  async reconstruct(requestId: string, responseText: string): Promise<ReconstructResult> {
    const result = await reconstructResponse(requestId, responseText, this.vault);

    const records = await this.vault.getAll(requestId);
    const typeByToken = new Map(records.map((r) => [r.token, r.type]));
    const restoredEntities = result.restoredTokens.map((token) => ({
      type: typeByToken.get(token) ?? "UNKNOWN",
    }));
    this.auditSink.record(buildAuditEvent(requestId, "reconstruct", restoredEntities));

    return result;
  }

  /**
   * Creates a reconstructor for a STREAMED provider response. Unlike
   * `reconstruct()`, which needs the whole response, this restores values
   * incrementally and safely handles placeholder tokens split across chunks.
   */
  async createStreamingReconstructor(requestId: string): Promise<StreamingReconstructor> {
    return createStreamingReconstructorImpl(requestId, this.vault);
  }

  /** Clears vault entries for a completed exchange. Call after reconstruction if not relying on TTL expiry. */
  async clearSession(requestId: string): Promise<void> {
    await this.vault.deleteAll(requestId);
  }

  /** Returns the audit trail (entity-type counts only - never raw values). */
  getAuditEvents(): AuditEvent[] {
    return this.auditSink.getEvents();
  }
}
