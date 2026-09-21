# Threat model of the audit platform itself (spec 38)

| threat | control |
|---|---|
| Scanning unauthorized systems | explicit authorization confirmation required for network/DAST; `target_authorized()` enforces loopback/private default scope; public targets need allowlist entry **and** `allow_external_targets: true` |
| Malicious archive input | `safe_extract_zip()` rejects absolute paths, `..` traversal, symlink members; extraction confined to workspace via `is_within()` |
| Executing scanned project code | SAST/settings analysis is pure AST parsing; settings are never imported; app startup only inside the sandbox step, loopback-bound, with timeout |
| Secret leakage via reports/evidence | `mask_secrets()` applied at evidence creation (AWS/GitHub/Stripe/PEM/generic credential patterns); settings snapshot masks SECRET/KEY/PASSWORD values |
| GitHub token exposure | tokens only used in clone URL, masked out of error output and logs |
| Path traversal in scanners | all file access resolved and confined to the audit workspace; symlink copies rejected (`copy_to_workspace(symlinks=False)`) |
| SSRF via platform features | DAST probes use fixed canary hosts; no user-controlled outbound fetches by the platform itself |
| Platform account compromise | scrypt-hashed passwords, 32-byte random bearer tokens, RBAC (`admin/analyst/viewer`), users file chmod 0600, mutating API actions audit-logged to `audit.log` (JSONL) |
| Scanner crash killing audits | every scanner runs via `safe_run()`; failures become `FAILED` job states, never exceptions; dependent requirements become `NOT_TESTED`, never `PASS` |
| Resource exhaustion | per-scan timeouts, sandbox process group cleanup, Docker compose resource limits (cpu/mem/pids), bounded HTTP reads (1 MB) |

## Residual risks

- `runserver` fallback runs the target's code on the auditor host: prefer the
  Docker path; GitHub-sourced projects refuse the fallback by default.
- The embedded advisory DB is a curated subset; integrate pip-audit/safety
  for production coverage.
- DAST login automation is best-effort; unauthenticated flows are covered
  regardless.
