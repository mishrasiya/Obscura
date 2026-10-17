import { GoogleGenerativeAI, GenerativeModel, ModelParams, GenerateContentRequest, GenerateContentResult, Part } from "@google/generative-ai";
import type { SanitizerConfig } from "@obscura/core";
import { BaseObscuraClient } from "../base.js";

/** Accepts the same inputs as `GenerativeModel.generateContent`. */
export type GeminiGenerateContentInput = GenerateContentRequest | string | Array<string | Part>;

/**
 * Drop-in, privacy-preserving wrapper around the Gemini SDK
 * (`@google/generative-ai`). Sanitizes all text parts of a request before
 * sending it, and restores reversible placeholders in the generated text.
 *
 * ```ts
 * const client = new ObscuraGemini(process.env.GEMINI_API_KEY!);
 * const model = client.getGenerativeModel({ model: "gemini-1.5-pro" });
 * const result = await model.generateContent("My phone number is 555-123-4567...");
 * console.log(result.response.text());
 * ```
 */
export class ObscuraGemini extends BaseObscuraClient {
  private readonly client: GoogleGenerativeAI;

  constructor(apiKey: string, sanitizerConfig: SanitizerConfig = {}) {
    super(sanitizerConfig);
    this.client = new GoogleGenerativeAI(apiKey);
  }

  getGenerativeModel(params: ModelParams): { generateContent: (input: GeminiGenerateContentInput) => Promise<GenerateContentResult> } {
    const model: GenerativeModel = this.client.getGenerativeModel(params);

    return {
      generateContent: async (input: GeminiGenerateContentInput): Promise<GenerateContentResult> => {
        const request = normalizeRequest(input);
        const { texts, refs } = extractPartTexts(request);

        const { requestId, sanitizedTexts } = await this.sanitizer.sanitizeBatch(texts);

        refs.forEach((ref, idx) => {
          const part = request.contents[ref.contentIndex].parts[ref.partIndex] as { text: string };
          part.text = sanitizedTexts[idx];
        });

        const result = await model.generateContent(request);

        const originalText = result.response.text();
        const { reconstructedText } = await this.sanitizer.reconstruct(requestId, originalText);
        await this.sanitizer.clearSession(requestId);

        // Wrap `.text()` so callers see the reconstructed value while the rest
        // of the response object (usage metadata, candidates, etc.) passes through.
        return {
          ...result,
          response: {
            ...result.response,
            text: () => reconstructedText,
          },
        } as GenerateContentResult;
      },
    };
  }
}

interface PartRef {
  contentIndex: number;
  partIndex: number;
}

function normalizeRequest(input: GeminiGenerateContentInput): GenerateContentRequest {
  if (typeof input === "string") {
    return { contents: [{ role: "user", parts: [{ text: input }] }] };
  }
  if (Array.isArray(input)) {
    const parts: Part[] = input.map((p) => (typeof p === "string" ? { text: p } : p));
    return { contents: [{ role: "user", parts }] };
  }
  // Deep-clone so we don't mutate the caller's request object.
  return JSON.parse(JSON.stringify(input)) as GenerateContentRequest;
}

function extractPartTexts(request: GenerateContentRequest): { texts: string[]; refs: PartRef[] } {
  const texts: string[] = [];
  const refs: PartRef[] = [];
  request.contents.forEach((content, ci) => {
    content.parts.forEach((part, pi) => {
      if ("text" in part && typeof part.text === "string") {
        texts.push(part.text);
        refs.push({ contentIndex: ci, partIndex: pi });
      }
    });
  });
  return { texts, refs };
}
