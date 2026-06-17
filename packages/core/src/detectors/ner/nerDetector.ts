import { DetectedEntity, EntityType } from "../../types.js";

/**
 * Lazily-loaded NER pipeline. The model is downloaded/cached on first use
 * via @xenova/transformers (runs fully locally via ONNX runtime - no data
 * leaves the process for entity detection).
 */
let pipelinePromise: Promise<any> | null = null;

const MODEL_NAME = "Xenova/bert-base-NER";

async function getPipeline(): Promise<any> {
  if (!pipelinePromise) {
    pipelinePromise = (async () => {
      const { pipeline } = await import("@xenova/transformers");
      return pipeline("token-classification", MODEL_NAME);
    })();
  }
  return pipelinePromise;
}

const GROUP_TO_ENTITY: Record<string, EntityType | undefined> = {
  PER: EntityType.PERSON_NAME,
  ORG: EntityType.ORGANIZATION,
  LOC: EntityType.LOCATION,
  // MISC is too broad/noisy to map to a single entity type and is skipped.
};

interface RawToken {
  /** IOB2 tag, e.g. "B-PER", "I-PER", "O". */
  entity: string;
  score: number;
  /** Decoded wordpiece, possibly prefixed with "##" for sub-word continuations. */
  word: string;
}

interface TokenGroup {
  tagType: string; // e.g. "PER", without the B-/I- prefix
  tokens: RawToken[];
}

/**
 * Groups consecutive IOB2 tokens into entity spans. A new group starts on
 * any "B-" tag, or on an "I-" tag whose type differs from the current group
 * (defensive against malformed tag sequences).
 */
function groupTokens(tokens: RawToken[]): TokenGroup[] {
  const groups: TokenGroup[] = [];
  let current: TokenGroup | null = null;

  for (const tok of tokens) {
    const [prefix, type] = tok.entity.includes("-") ? tok.entity.split("-") : ["O", "O"];
    if (type === "O") {
      current = null;
      continue;
    }
    if (prefix === "B" || !current || current.tagType !== type) {
      current = { tagType: type, tokens: [] };
      groups.push(current);
    }
    current.tokens.push(tok);
  }

  return groups;
}

/**
 * Locates the character span of a token group within `text`, walking
 * forward from `searchFrom`. Handles "##"-prefixed sub-word continuations
 * (concatenated directly onto the previous token) by searching for each
 * standalone word and growing the span across continuations.
 *
 * Returns `null` if any token's text cannot be located, since unreliable
 * offsets would corrupt downstream masking.
 */
function locateSpan(text: string, group: TokenGroup, searchFrom: number): { start: number; end: number } | null {
  let start: number | undefined;
  let end = searchFrom;

  for (const tok of group.tokens) {
    const isContinuation = tok.word.startsWith("##");
    const clean = isContinuation ? tok.word.slice(2) : tok.word;
    if (!clean) continue;

    if (isContinuation && start !== undefined) {
      // Sub-word continuations attach directly to the preceding token.
      if (text.slice(end, end + clean.length) !== clean) return null;
      end = end + clean.length;
      continue;
    }

    const idx = text.indexOf(clean, end);
    if (idx === -1) return null;
    if (start === undefined) start = idx;
    end = idx + clean.length;
  }

  if (start === undefined) return null;
  return expandToWordBoundary(text, start, end);
}

const WORD_CHAR = /[A-Za-z0-9]/;

/**
 * Expands a span to whole-word boundaries. WordPiece tokenization can split
 * a single word across multiple tokens that the model tags inconsistently
 * (e.g. tagging "Jane Do" as PERSON but leaving the trailing "##e" as "O").
 * Replacing only the tagged portion would fragment the surrounding word
 * (`[PERSON_NAME_1]e`), so we snap to the full word on either side.
 */
function expandToWordBoundary(text: string, start: number, end: number): { start: number; end: number } {
  while (start > 0 && WORD_CHAR.test(text[start - 1])) start--;
  while (end < text.length && WORD_CHAR.test(text[end])) end++;
  return { start, end };
}

// BERT's positional embeddings cap input at 512 wordpiece tokens. Feeding
// longer text doesn't truncate gracefully - @xenova/transformers silently
// returns near-empty/garbage output for the *entire* input once that limit
// is exceeded, so even entities near the start (e.g. the first PERSON name)
// go undetected. Conservatively chunk well under that limit by character
// count, splitting on whitespace/newlines so words aren't broken apart.
const MAX_CHUNK_CHARS = 1000;

/** Splits `text` into chunks of at most `MAX_CHUNK_CHARS`, each tagged with its offset into the original text. */
function splitIntoChunks(text: string): Array<{ text: string; offset: number }> {
  if (text.length <= MAX_CHUNK_CHARS) return [{ text, offset: 0 }];

  const chunks: Array<{ text: string; offset: number }> = [];
  let chunkStart = 0;

  while (chunkStart < text.length) {
    if (text.length - chunkStart <= MAX_CHUNK_CHARS) {
      chunks.push({ text: text.slice(chunkStart), offset: chunkStart });
      break;
    }

    const window = text.slice(chunkStart, chunkStart + MAX_CHUNK_CHARS);
    let splitAt = window.lastIndexOf("\n");
    if (splitAt <= 0) splitAt = window.lastIndexOf(" ");
    if (splitAt <= 0) splitAt = MAX_CHUNK_CHARS; // no whitespace found - hard split

    chunks.push({ text: text.slice(chunkStart, chunkStart + splitAt), offset: chunkStart });
    chunkStart += splitAt;
    while (chunkStart < text.length && /\s/.test(text[chunkStart])) chunkStart++;
  }

  return chunks;
}

/**
 * Detects PERSON, ORGANIZATION, and LOCATION entities using a local
 * transformer NER model. Complements the regex detectors, which do not
 * cover free-form names/places.
 *
 * @param text input text
 * @param minConfidence entities scoring below this are discarded (default 0.6)
 */
export async function detectWithNer(text: string, minConfidence = 0.6): Promise<DetectedEntity[]> {
  if (!text.trim()) return [];

  const classifier = await getPipeline();
  const results: DetectedEntity[] = [];

  for (const chunk of splitIntoChunks(text)) {
    if (!chunk.text.trim()) continue;

    const rawTokens: RawToken[] = await classifier(chunk.text);
    const groups = groupTokens(rawTokens);
    let cursor = 0;

    for (const group of groups) {
      const type = GROUP_TO_ENTITY[group.tagType];
      if (!type) continue;

      const avgScore = group.tokens.reduce((sum, t) => sum + t.score, 0) / group.tokens.length;
      if (avgScore < minConfidence) continue;

      const span = locateSpan(chunk.text, group, cursor);
      if (!span) continue;

      results.push({
        type,
        category: "PII",
        value: chunk.text.slice(span.start, span.end),
        start: span.start + chunk.offset,
        end: span.end + chunk.offset,
        confidence: avgScore,
        source: "ner",
      });

      cursor = span.end;
    }
  }

  return results;
}

/** Pre-warms the NER model so the first real request doesn't pay the load cost. */
export async function warmupNer(): Promise<void> {
  await getPipeline();
}
