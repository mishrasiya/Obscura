import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer, EntityType } from "../index.js";

test("repeated identical values reuse a single token", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });

  // Same facility named twice (ORGANIZATION rule is regex-based, so NER is off).
  const text =
    "Admitted to St. Jude Regional Medical Center; discharge handled by St. Jude Regional Medical Center.";
  const { requestId, sanitizedText } = await sanitizer.sanitize(text);

  // Both mentions collapse to the SAME token (not _1 and _2).
  const tokens = sanitizedText.match(/\[ORGANIZATION_\d+\]/g) ?? [];
  assert.equal(tokens.length, 2, "both mentions should be tokenized");
  assert.equal(tokens[0], tokens[1], "identical values must reuse one token");

  const { reconstructedText } = await sanitizer.reconstruct(requestId, sanitizedText);
  assert.equal(reconstructedText, text, "reconstruction restores every occurrence");
});

test("surname propagation masks a related name NER missed", async () => {
  // Seed two family members as known (stand-in for NER having tagged them);
  // the third shares the surname but is never seeded/tagged.
  const sanitizer = new Sanitizer({
    enableNer: false,
    knownEntities: [
      { value: "Arthur Pendelton", type: EntityType.PERSON_NAME },
      { value: "Beatrice Pendelton", type: EntityType.PERSON_NAME },
    ],
  });
  const text = "Arthur Pendelton, Beatrice Pendelton. Prepared by Marcus Pendelton.";
  const { sanitizedText } = await sanitizer.sanitize(text);

  assert.ok(!sanitizedText.includes("Marcus Pendelton"), "Marcus Pendelton must be masked via surname");
  assert.ok(!sanitizedText.includes("Pendelton"), "no surname should remain in plain text");
});

test("distinct values still get distinct tokens", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });
  const { sanitizedText } = await sanitizer.sanitize(
    "Email alice@example.com and bob@example.com."
  );
  assert.match(sanitizedText, /\[EMAIL_1\]/);
  assert.match(sanitizedText, /\[EMAIL_2\]/);
});
