# Contribute to VMgrab

Thank you for your interest in contributing to VMgrab.

VMgrab is developed and maintained by **enclaive.io** as an offensive security research & validation tool for confidential VM encryption enforcement (AMD SEV-SNP / Intel TDX).

This project requires *high discipline*, *rigorous engineering*, and *ethical alignment*.

**Important note:** You may only use this tool — and contribute code/testing — against infrastructure **you own** or have **explicit written permission** to assess.


## Contribution Model

We follow a strict quality-first principle.

You contribute by:

* hardening acquisition techniques
* improving analysis accuracy
* adding parsers, exporters, tooling
* improving reproducibility & research-validated test harnesses
* aligning ecosystem integrations (CI/CD, artifact signing, packaging)

We do **NOT** accept:

* exploit tutorials
* blackhat usage guides
* memory dumps from real production systems
* sensitive live data

## How to start

```bash
git clone github.com:enclaive/vmgrab.git
cd vmgrab
```

Create your feature branch:

```bash
git checkout -b feat/<short_description>
```

Before opening PRs:

* run formatters
* run unit tests
* run integration tests (sandbox env only)

## Commit Hygiene

Use short atomic commits.

Commit types:

* feat
* fix
* refactor
* test
* docs
* chore

## Pull Requests

* must remain focused
* must contain tests
* must pass CI
* must include rationale (why this matters)

Large design changes require review from maintainers beforehand (open an issue first).

## Responsible Disclosure

Security-relevant findings must be reported privately.

Public issues must not contain exploit details, memory dumps, or sensitive reproduction context.

Refer to `SECURITY.md` for private channel.

## Licensing

All contributions must be compatible with MIT License.

MIT license file is included in the repository.

## Project Home

**enclaive.io** — Confidential Computing for Offensive Verification

Repo:
[https://github.com/enclaive/vmgrab](https://github.com/enclaive/vmgrab)
