import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer } from "../index.js";

test("streaming reconstructor restores a token split across chunk boundaries", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });
  const { requestId } = await sanitizer.sanitize("Email me at jane@example.com please.");

  const recon = await sanitizer.createStreamingReconstructor(requestId);
  // The placeholder [EMAIL_1] is deliberately split across several chunks.
  const chunks = ["Sure, I'll ", "write to [EMA", "IL_1] to", "day."];
  let out = "";
  for (const c of chunks) out += recon.push(c);
  out += recon.flush();

  assert.equal(out, "Sure, I'll write to jane@example.com today.");
  assert.deepEqual([...recon.restoredTokens], ["[EMAIL_1]"]);
});

test("streaming reconstructor passes through unknown tokens and literal brackets", async () => {
  const sanitizer = new Sanitizer({ enableNer: false });
  const { requestId } = await sanitizer.sanitize("hello world");

  const recon = await sanitizer.createStreamingReconstructor(requestId);
  let out = recon.push("value is [UNK");
  out += recon.push("NOWN_9] and [ literal");
  out += recon.flush();

  assert.equal(out, "value is [UNKNOWN_9] and [ literal");
  assert.ok(out.endsWith("[ literal"));
});
