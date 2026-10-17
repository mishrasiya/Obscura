// Build-time warmup: downloads the local NER model (Xenova/bert-base-NER) and
// caches it into the image so the first request at runtime is fast and the
// container does not need HuggingFace network access to boot.
import { Sanitizer } from "@obscura/core";

const s = new Sanitizer({ knownEntitiesFile: "/tmp/warmup-entities.json" });
await s.warmup();
console.log("NER model downloaded and cached.");
