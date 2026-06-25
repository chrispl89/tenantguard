# Contributing to TenantGuard

Thank you for your interest in contributing.

TenantGuard is a defensive authorization regression testing tool. Contributions should strengthen safe, authorized testing workflows for SaaS applications.

## Good contribution ideas

- clearer validation messages,
- safer defaults,
- better documentation,
- additional assertion types,
- improved report formats,
- demo applications for education,
- CI examples,
- test coverage,
- bug fixes in config handling or safety guards.

## Out of scope

Please do not open pull requests that add:

- brute-force functionality,
- stealth scanning,
- rate-limit bypass mechanisms,
- exploit payloads,
- unauthorized third-party scanning features,
- features that encourage testing systems without permission.

## Development setup

```bash
git clone https://github.com/chrispl89/tenantguard.git
cd tenantguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run checks:

```bash
ruff check .
mypy tenantguard
pytest
```

## Code style

- Python 3.11+
- type hints required
- English comments and docstrings
- keep modules focused and explicit
- do not log secrets or tokens

## Pull requests

- explain the problem and the proposed solution,
- include tests when behavior changes,
- keep changes focused,
- ensure CI passes.
