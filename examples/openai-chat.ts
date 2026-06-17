/**
 * Example: drop-in replacement for the OpenAI SDK that sanitizes PII/PHI/
 * secrets before they reach OpenAI, and restores them in the response.
 *
 * Run with: OPENAI_API_KEY=sk-... npx tsx examples/openai-chat.ts
 */
import { PrivacyGuardOpenAI } from "@privacyguard/sdk";

async function main() {
  const client = new PrivacyGuardOpenAI({ apiKey: process.env.OPENAI_API_KEY });

  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content:
          "Write a one-sentence reminder email to jane.doe@example.com about her appointment.",
      },
    ],
  });

  console.log(completion.choices[0].message.content);
  console.log("\nAudit trail:", JSON.stringify(client.getAuditEvents(), null, 2));
}

main();
