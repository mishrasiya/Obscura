import OpenAI from "openai";
import type {
  ChatCompletion,
  ChatCompletionCreateParamsNonStreaming,
  ChatCompletionMessageParam,
} from "openai/resources/chat/completions";
import type { SanitizerConfig } from "@privacyguard/core";
import { BasePrivacyGuardClient } from "../base.js";
import { extractTexts, rebuildWithTexts, TextRef } from "../textExtraction.js";

export interface PrivacyGuardOpenAIOptions {
  apiKey?: string;
  baseURL?: string;
  organization?: string;
}

/**
 * Drop-in, privacy-preserving wrapper around the OpenAI SDK's chat
 * completions API. Before forwarding a request, all message text content is
 * scanned for PII/PHI/secrets and masked according to policy. After the
 * response is returned, any reversible placeholders are restored so the
 * caller sees the original values.
 *
 * Usage mirrors the official SDK:
 *
 * ```ts
 * const client = new PrivacyGuardOpenAI({ apiKey: process.env.OPENAI_API_KEY });
 * const completion = await client.chat.completions.create({
 *   model: "gpt-4o",
 *   messages: [{ role: "user", content: "My email is jane@example.com..." }],
 * });
 * ```
 *
 * Note: streaming responses are not yet supported; `stream` is forced to `false`.
 */
export class PrivacyGuardOpenAI extends BasePrivacyGuardClient {
  private readonly client: OpenAI;

  constructor(options: PrivacyGuardOpenAIOptions = {}, sanitizerConfig: SanitizerConfig = {}) {
    super(sanitizerConfig);
    this.client = new OpenAI(options);
  }

  /** Access to the underlying, unwrapped OpenAI client for endpoints not covered by this wrapper. */
  get raw(): OpenAI {
    return this.client;
  }

  get chat() {
    return {
      completions: {
        create: (params: ChatCompletionCreateParamsNonStreaming) => this.createChatCompletion(params),
      },
    };
  }

  private async createChatCompletion(params: ChatCompletionCreateParamsNonStreaming): Promise<ChatCompletion> {
    const messages = params.messages;
    const { texts, refs } = extractTexts(messages);

    const { requestId, sanitizedTexts } = await this.sanitizer.sanitizeBatch(texts);

    const sanitizedMessages = rebuildWithTexts(messages, refs, sanitizedTexts);

    const response = await this.client.chat.completions.create({
      ...params,
      messages: sanitizedMessages,
      stream: false,
    });

    for (const choice of response.choices) {
      if (choice.message?.content) {
        const { reconstructedText } = await this.sanitizer.reconstruct(requestId, choice.message.content);
        choice.message.content = reconstructedText;
      }
    }

    await this.sanitizer.clearSession(requestId);
    return response;
  }
}

/** Reference type re-exported for advanced/custom integrations. */
export type { TextRef };
