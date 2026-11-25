import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer, EntityType } from "../../index.js";
import { detectObfuscated } from "./obfuscationDetector.js";

test("spelled-out SSN is detected", () => {
  const found = detectObfuscated(
    "her SSN is zero-zero-zero, dash, four-five, dash, six-seven-eight-nine today"
  );
  assert.ok(found.some((e) => e.type === EntityType.SSN), "expected an SSN");
});

test("mixed word/digit phone is detected", () => {
  const found = detectObfuscated("Call (312) five-five-five - 0194 now");
  assert.ok(found.some((e) => e.type === EntityType.PHONE_NUMBER), "expected a phone number");
});

test("pure-digit and plain-word runs are left to other detectors / ignored", () => {
  // No spelled number word -> not handled here (regex rules own pure digits).
  assert.equal(detectObfuscated("call 3125550194 today").length, 0);
  // Spelled words but too few digits -> ignored.
  assert.equal(detectObfuscated("I bought four apples and three oranges").length, 0);
});

test("end-to-end: obfuscated intake note masks every sensitive value", async () => {
  const s = new Sanitizer({ enableNer: false });
  const prompt =
    "SSN zero-zero-zero, dash, four-five, dash, six-seven-eight-nine; " +
    "MBI is 2 S A 9 - T E 4 - M K 8 8; group/policy GRP-9921 / W204819204; " +
    "landline (312) five-five-five - 0194; email eleanor [dot] vance93 [at] example [dot] com; age 93.";
  const { sanitizedText, entities } = await s.sanitize(prompt);

  const types = new Set(entities.map((e) => e.type));
  for (const t of [
    EntityType.SSN,
    EntityType.HEALTH_INSURANCE_ID,
    EntityType.PHONE_NUMBER,
    EntityType.EMAIL,
    EntityType.AGE,
  ]) {
    assert.ok(types.has(t), `expected ${t} to be detected`);
  }

  // Nothing identifiable should survive in the clear.
  for (const leak of ["six-seven-eight-nine", "five-five-five", "vance93", "W204819204", "GRP-9921", "2 S A 9"]) {
    assert.ok(!sanitizedText.includes(leak), `"${leak}" leaked`);
  }
});
