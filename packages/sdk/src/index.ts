export { PrivacyGuardOpenAI } from "./clients/PrivacyGuardOpenAI.js";
export type { PrivacyGuardOpenAIOptions } from "./clients/PrivacyGuardOpenAI.js";

export { PrivacyGuardAnthropic } from "./clients/PrivacyGuardAnthropic.js";
export type { PrivacyGuardAnthropicOptions } from "./clients/PrivacyGuardAnthropic.js";

export { PrivacyGuardGemini } from "./clients/PrivacyGuardGemini.js";
export type { GeminiGenerateContentInput } from "./clients/PrivacyGuardGemini.js";

export { BasePrivacyGuardClient } from "./base.js";

// Re-export the core engine so consumers can configure policies/rules
// without a separate dependency on @privacyguard/core.
export * from "@privacyguard/core";
