import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer, MaskingStrategy, EntityType } from "./index.js";

test("redacts secrets and tokenizes PII, then reconstructs the response", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });

  const prompt =
    "Hi, my name is John Smith, my email is john.smith@example.com and my AWS key is AKIAIOSFODNN7EXAMPLE.";

  const { requestId, sanitizedText, entities } = await sanitizer.sanitize(prompt);

  // Secrets are redacted, not forwarded.
  assert.ok(!sanitizedText.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.match(sanitizedText, /\[REDACTED_AWS_ACCESS_KEY\]/);

  // PII is tokenized.
  assert.ok(!sanitizedText.includes("john.smith@example.com"));
  assert.match(sanitizedText, /\[EMAIL_1\]/);

  assert.ok(entities.some((e) => e.type === EntityType.EMAIL));
  assert.ok(entities.some((e) => e.type === EntityType.AWS_ACCESS_KEY));

  // Simulate an LLM response that echoes back the placeholder.
  const llmResponse = "Sure, I'll email you at [EMAIL_1] shortly.";
  const { reconstructedText, restoredTokens } = await sanitizer.reconstruct(requestId, llmResponse);

  assert.equal(reconstructedText, "Sure, I'll email you at john.smith@example.com shortly.");
  assert.deepEqual(restoredTokens, ["[EMAIL_1]"]);
});

test("custom rules and PARTIAL_MASK/HASH/ALLOW strategies", async () => {
  const sanitizer = new Sanitizer({
    enableNer: false,
    policy: {
      [EntityType.CREDIT_CARD]: MaskingStrategy.PARTIAL_MASK,
      [EntityType.IP_ADDRESS]: MaskingStrategy.HASH,
    },
    customRules: [
      {
        name: "PROJECT_CODENAME",
        pattern: /Project[ -]?Nightingale/gi,
        category: "PII",
        strategy: MaskingStrategy.TOKENIZE,
      },
    ],
  });

  const text = "Card 4111 1111 1111 1111 from 192.168.1.1 regarding Project Nightingale.";
  const { sanitizedText } = await sanitizer.sanitize(text);

  assert.match(sanitizedText, /\*\*\*\*1111/);
  assert.match(sanitizedText, /\[IP_ADDRESS_HASH_[0-9a-f]{10}\]/);
  assert.match(sanitizedText, /\[PROJECT_CODENAME_1\]/);
});

test("sanitizeBatch keeps consistent token numbering across multiple texts", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });

  const { requestId, sanitizedTexts } = await sanitizer.sanitizeBatch([
    "Contact alice@example.com for details.",
    "Also reach bob@example.com if needed.",
  ]);

  assert.match(sanitizedTexts[0], /\[EMAIL_1\]/);
  assert.match(sanitizedTexts[1], /\[EMAIL_2\]/);

  const { reconstructedText } = await sanitizer.reconstruct(requestId, "[EMAIL_1] and [EMAIL_2]");
  assert.equal(reconstructedText, "alice@example.com and bob@example.com");
});
