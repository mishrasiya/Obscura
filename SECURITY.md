# Security Policy

Obscura is a privacy middleware whose entire purpose is to keep sensitive data
out of third-party LLM providers. We take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Email **security@benevolo.ai** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal prompt or request is ideal — but **never send
  real PII/PHI**; use synthetic data),
- affected version/commit.

We aim to acknowledge reports within **2 business days** and to provide a
remediation timeline within **5 business days**. We will credit reporters who
wish to be credited once a fix is released.

## Scope

In scope:

- The sanitization engine (`@obscura/core`): detector bypasses that let real
  PII/PHI/secrets reach an upstream provider, vault leaks, reconstruction
  returning the wrong value to the wrong request/session.
- The proxy (`apps/proxy`) and demo (`apps/demo-ui`): authentication bypass,
  per-client key leakage, log/response leakage of prompt content or vault
  values, SSRF to the upstream, injection.

Particularly valuable reports:

- Any input that causes a **real sensitive value to be forwarded upstream** or
  to appear **in a log line, error response, or audit record**.
- Any cross-request or cross-tenant vault/reconstruction leak.

Out of scope:

- Detection recall gaps that are already documented in
  [`docs/known-gaps.md`](docs/known-gaps.md) and the HIPAA mapping. Obscura is a
  risk-reduction layer, not a guarantee of 100% detection; see those docs for
  known limitations. New, undocumented classes of missed data **are** in scope.

## Supported versions

Pre-1.0, only the latest `0.x` minor receives security fixes. Pin a version and
watch releases.

## Our commitments

- Real detected values are never written to logs or audit records (audit stores
  entity-type counts only).
- The vault is encrypted at rest (AES-256-GCM) and entries expire by TTL.
- We disclose known detection gaps honestly rather than overstating coverage.
