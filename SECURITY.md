# Security Policy

**Last updated:** 2025-11-12

Thank you for taking the time to responsibly disclose security issues. This document explains how to report vulnerabilities, what to expect after reporting, and how we handle disclosures for this project.


## Supported Versions

We support the following branches / releases:

* `main` (rolling development)
* Releases with tags `v*.*.*` — we consider the latest two stable minor versions actively supported for security fixes.

If you are unsure whether your issue affects a supported version, please include the exact Git tag/commit and build information in your report.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security reports.** Public issues could expose sensitive details before a fix is available.

Preferred contact methods:

1. **Email (if encryption not possible):** `security@enclaive.io`
2. If you do not receive an acknowledgement within the timeframe below, open a private ticket on GitHub by creating an issue with the label `security` and toggle the repository's private issue option, or contact a maintainer directly.

### What to include in your report

Please provide as much of the following as you can — it speeds up triage and remediation:

* Product name and exact version (git tag / commit SHA / docker image digest)
* Affected component(s) and a short summary of the impact
* Step-by-step reproduction steps and a minimal PoC (proof-of-concept), scripts, or testcases that reproduce the issue
* Expected vs actual behavior
* Any logs, stack traces or screenshots
* Network captures (pcap) or sample data (sanitized) if applicable
* Your contact information and whether you consent to public attribution (name/handle)

If you prefer not to share PoCs publicly, we will coordinate a private disclosure and a fix prior to public release.


## Response Timeline & Process

We aim to handle reports as follows (calendar days):

1. **Acknowledgement:** within **3 business days** (we'll confirm receipt and share the expected triage timeline).
2. **Triage & initial assessment:** within **7 days** (we classify severity and plan the response).
3. **Fix/mitigation:** timing depends on severity and complexity. For critical issues we strive for emergency patches; for lower-severity issues we schedule fixes into the next appropriate release.
4. **Coordinated public disclosure:** we will coordinate with you on the public disclosure timeline. Our default disclosure window is **90 days** from initial contact for most issues; this can be shortened or extended by mutual agreement depending on the complexity and severity.


## Severity Ratings

These are illustrative; final classification is done during triage.

* **Critical** — Remote code execution or authorization bypass affecting default deployments with no feasible mitigation; immediate action required.
* **High** — Privilege escalation, data exfiltration, server compromise under realistic conditions.
* **Medium** — Information disclosure requiring user interaction, local privilege issues with limited impact.
* **Low** — Minor information leak, UX issues, or edge-case bugs with minimal security impact.


## Safe Testing Guidelines

When testing for vulnerabilities, please:

* Only test systems you own or have explicit written permission to test.
* Prefer using local VMs, containers, or an isolated test network.
* Avoid destructive testing on production systems.
* If exploitation requires sensitive data, provide sanitized artifacts in your report.


## Disclosure & Credit

We appreciate responsible disclosure. After a fix is deployed and coordinated disclosure agreed, we will:

* Credit the reporter in our `SECURITY.md` or `AUTHORS` file (with your consent).
* Optionally create a security advisory and request a CVE if appropriate.

If you do not want public credit, please say so in your report.


## Legal Safe Harbor

We will not pursue legal action against individuals acting in good faith to report security vulnerabilities in accordance with this policy. That said, testing that violates explicit laws or causes damage is not permitted. If you are unsure about the legal status of your testing, consult your legal counsel.


## Submit a Patch

Contributors who can provide a fix are welcome to submit a pull request. Please:

1. Fork the repository and create a branch named `fix/security-<short-desc>`.
2. Include tests that demonstrate the vulnerability and the fix (unit/integration tests where applicable).
3. Sign your commit with your GPG key if possible and add a note in the PR about security impact and the related report.
4. For sensitive fixes, contact us via the private channels above before opening a public PR — we may prefer to land the fix on a private branch first.


## CVE Requests

If a report warrants a CVE, we will request one on your behalf or jointly with you. Indicate in your report if you would like us to request a CVE.


## Contact

Secure reporting email: `security@enclaive.io


## Acknowledgements

Thanks to everyone who helps keep this project secure. Your responsible disclosures protect our users and help us improve.

*This policy is a template — please edit contact addresses, PGP key, and timelines to match your project’s practice.*
