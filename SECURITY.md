# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

If you find a security issue in TemrenSec itself, please **do not** open a public
GitHub issue. Instead:

1. Email `security@zerosixlab.com` (PGP key on request).
2. Include reproduction steps, affected version, and the impact you observed.
3. Allow up to 5 business days for an acknowledgement.

We aim to:
- Acknowledge receipt within 5 business days
- Provide a remediation plan within 30 days
- Publish a coordinated disclosure (CVE if applicable) once a fix has been released

## Out of scope

The scanner intentionally probes for vulnerabilities, so the following are
expected behaviour, not security issues:
- Sending non-RFC-compliant HTTP frames (request smuggling probes)
- Connecting to cloud metadata endpoints
- Submitting crafted bodies that deserializers may reject loudly

If unsure, please report it — we would rather triage a duplicate than miss a real issue.

## Plugin threat model

Temren supports user-supplied Lua plugins (loaded from `--plugins-dir`).
The Lua VM is constrained:

- Only `base`, `table`, `string`, `math` standard libs are opened.
- `require`, `package`, `module`, `dofile`, `loadfile`, `load`, `loadstring`,
  `io`, `os`, `debug` globals are stripped after lib load.
- Memory is capped (64 MB per VM via `LState.SetMx`).
- Every invocation has a 30s deadline enforced via `LState.SetContext`,
  so a busy-loop plugin can't deadlock the scan worker.
- Call stack and registry sizes are bounded.

This is **defence-in-depth, not a security boundary** against a determined
attacker. Lua plugins still:
- run in-process with the scanner,
- can pin CPU until the 30s deadline trips,
- can accumulate state across invocations (per-plugin VM is persistent).

Treat plugins like shell scripts checked into your repo: only load code
you wrote or audited. If you need stronger isolation (untrusted plugin
marketplace, multi-tenant SaaS), wrap plugin execution in the
`pkg/sandbox` subprocess sandbox or run workers in a per-tenant container.

## Hall of fame

A list of researchers who responsibly disclosed issues will be maintained here.
