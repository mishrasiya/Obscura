# Contributing to Obscura

Thanks for your interest in improving Obscura. This project is a privacy
middleware for LLM prompts, so contributions are held to one hard rule above all
others:

> **Never commit, log, or persist real sensitive data.** Use synthetic values in
> tests, examples, and bug reports. Values that merely *look* like credentials
> (e.g. `AKIAIOSFODNN7EXAMPLE`) must be non-functional placeholders.

## Development setup

Requires Node.js 20+ (CI tests 20, 22, 24) and npm 10+.

```bash
npm install          # install all workspaces
npm run build        # build @obscura/core, @obscura/sdk, apps/*
npm test             # run unit tests (NER-disabled, no network)
```

This is an npm-workspaces monorepo:

- `packages/core` — the detection/masking/vault/reconstruction engine. No
  network calls except the one-time local NER model download.
- `packages/sdk` — drop-in provider client wrappers.
- `apps/proxy` — the standalone OpenAI-compatible proxy.
- `apps/demo-ui` — the hosted demo.

## Making a change

1. Branch from `main`.
2. Keep changes small and focused; prefer small files.
3. **No new runtime dependencies** without justification in the PR description
   (what it's for, why a built-in won't do, license, size).
4. **Keep public APIs backwards compatible** within a minor version. Breaking
   changes to `@obscura/*` exports need a changeset note and a major/minor bump.
5. Add or update tests. Detector changes must include test cases (both the
   positive match and a near-miss that must *not* match).
6. Update `CHANGELOG.md` under `## [Unreleased]`.
7. Run `npm run build && npm test` before pushing.

## Detector contributions

- Add the pattern to `packages/core/src/detectors/regex/patterns.ts` and a type
  to `EntityType` if needed.
- Prefer label-anchored patterns for ambiguous numeric formats to avoid false
  positives (see existing `DRIVERS_LICENSE`, `BANK_ACCOUNT`).
- Update `docs/hipaa-mapping.md` if the change affects HIPAA identifier coverage.
- If it's a known gap you're documenting rather than fixing, add it to
  `docs/known-gaps.md`.

## Commit and PR conventions

- Conventional-commit style messages (`feat:`, `fix:`, `docs:`, `chore:`…).
- PRs should describe the behavior change and its privacy impact, if any.
- By contributing you agree your contribution is licensed under the project's
  [Apache-2.0 license](LICENSE).

## Reporting security issues

Do **not** use the public issue tracker. See [SECURITY.md](SECURITY.md).
