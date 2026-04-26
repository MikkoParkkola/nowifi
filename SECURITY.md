# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in nowifi, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

Email: [mikko.parkkola@iki.fi](mailto:mikko.parkkola@iki.fi)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for critical issues

### Scope

In scope:
- Command injection via user-supplied flags or network data
- Privilege escalation beyond intended sudo usage
- State restoration failures (MAC, proxy, DNS not cleaned up)
- Credential leakage in logs, captures, or config files
- Dependencies with known CVEs
- Regressions in privileged temp-file handling, authenticated proxy behavior,
  test isolation, checked downloads, or release integrity

Out of scope:
- The bypass techniques themselves (they are the intended functionality)
- Issues requiring physical access to the machine running nowifi
- Social engineering attacks

### Recognition

Security researchers who report valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.14.x  | Yes       |
| 0.13.x  | Security fixes only |
| < 0.13  | No        |

## Maintainer Regression Checklist

Security-sensitive pull requests should be checked against
[`docs/SECURITY-REGRESSION-CHECKLIST.md`](docs/SECURITY-REGRESSION-CHECKLIST.md)
before merge.
