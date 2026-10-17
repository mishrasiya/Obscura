/**
 * Minimal example: sanitize a prompt, "send" it to a (fake) LLM, then
 * reconstruct the response. Run with: npx tsx examples/basic-sanitize.ts
 */
import { Sanitizer } from "@obscura/core";

async function main() {
  const sanitizer = new Sanitizer();

  const prompt = [
    "Hi, I'm Jane Doe (jane.doe@example.com, 555-123-4567).",
    "My SSN is 123-45-6789 and my AWS key is AKIAIOSFODNN7EXAMPLE.",
    "Can you draft a follow-up email for me?",
  ].join(" ");

  const { requestId, sanitizedText, entities } = await sanitizer.sanitize(prompt);

  console.log("--- Detected entities ---");
  for (const e of entities) {
    console.log(`${e.type} (${e.source}, confidence ${e.confidence.toFixed(2)}): "${e.value}"`);
  }

  console.log("\n--- Text sent to the LLM provider ---");
  console.log(sanitizedText);

  // Pretend the LLM echoed the placeholder back in its reply.
  const fakeLlmResponse = "Sure thing! I'll send the follow-up to [EMAIL_1] right away.";

  const { reconstructedText } = await sanitizer.reconstruct(requestId, fakeLlmResponse);

  console.log("\n--- Reconstructed response shown to the user ---");
  console.log(reconstructedText);

  console.log("\n--- Audit trail (no raw values) ---");
  console.log(JSON.stringify(sanitizer.getAuditEvents(), null, 2));
}

main();
