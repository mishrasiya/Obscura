/**
 * Example: configuring custom masking policies and organization-specific
 * detection rules. Run with: npx tsx examples/custom-policy.ts
 */
import { Sanitizer, EntityType, MaskingStrategy } from "@obscura/core";

async function main() {
  const sanitizer = new Sanitizer({
    // Override defaults for specific entity types.
    policy: {
      // Show last 4 digits instead of fully tokenizing credit cards.
      [EntityType.CREDIT_CARD]: MaskingStrategy.PARTIAL_MASK,
      // Replace IP addresses with a stable, non-reversible hash.
      [EntityType.IP_ADDRESS]: MaskingStrategy.HASH,
      // Allow phone numbers through untouched (e.g. for a support-line context).
      [EntityType.PHONE_NUMBER]: MaskingStrategy.ALLOW,
    },
    // Detect and tokenize an internal project codename.
    customRules: [
      {
        name: "PROJECT_CODENAME",
        pattern: /Project[ -]?Nightingale/gi,
        category: "PII",
        strategy: MaskingStrategy.TOKENIZE,
      },
    ],
    // Disable the local NER model if you only need structured-pattern detection.
    enableNer: false,
  });

  const text =
    "Card 4111 1111 1111 1111 was used from 192.168.1.42 to discuss Project Nightingale. Call 555-987-6543 for support.";

  const { sanitizedText, entities } = await sanitizer.sanitize(text);

  console.log(sanitizedText);
  console.log(JSON.stringify(entities, null, 2));
}

main();
