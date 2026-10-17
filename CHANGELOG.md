# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.
- GitHub Actions CI: build + test across Node 20/22/24.

### Changed
- Completed the rename from "PrivacyGuard" to "Obscura" across all packages, the
  SDK client classes, and the demo (including the auth cookie `obscura_token`).

### Deployment
- Added a container image, Docker Compose stack with optional Caddy TLS, and an
  EC2 provisioning script under `deploy/`.

## [0.1.0]

### Added
- `@obscura/core`: regex + local NER detection, policy-driven masking
  (TOKENIZE / REDACT / HASH / PARTIAL_MASK / ALLOW), AES-256-GCM encrypted
  per-request vault, response reconstruction, and count-only audit logging.
- `@obscura/sdk`: drop-in privacy-preserving clients for OpenAI, Anthropic, and
  Gemini.
- `apps/demo-ui`: a web demo with auth, chat history, and a known-entities
  dictionary.
