# JIT CA — Codex repository guidance

## Purpose
JIT CA is a self-hosted development workbench for recovering cloud-dependent IoT devices **owned by the operator**. It provides DNS-triggered certificate prewarming, on-demand TLS termination, request observation, and synthetic responses. The long-term goal is a reusable framework for developing standalone local emulators of discontinued vendor cloud services (a Roomba cloud replacement is an example of the class of project, not an already implemented adapter).

Start by reading `README.md` and `CODEX_HANDOFF.md`. Treat them as the current implementation summary and target roadmap respectively. Do not infer implementation from the roadmap.

## Existing code
- `jitca/certs.py`: issuer setup, PEM validation, signed leaf generation, persistent cache.
- `jitca/service.py`: DNS listener, certificate prewarming, SNI TLS server, simple HTTP response handler and capture logging.
- `jitca/events.py`: asynchronous JSONL event writer, queue draining and storage error reporting.
- `jitca/config.py`: TOML configuration and policy checks.
- `jitca/cli.py`: Typer CLI.
- `tests/test_e2e.py`: integration tests that exercise real loopback DNS and TLS.
- `config.example.toml`: safe loopback-only example configuration.

## Run / test
```
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
cp config.example.toml config.toml
jitca --config config.toml serve
# In another terminal: python demo.py
```
The initial package was verified with `5 passed` tests. Re-run after any code change.

## Engineering constraints
- Python-first design; prefer typed, modular APIs with focused integration tests.
- No automatic interception of unregistered devices or hostnames; default to loopback and allowlisted endpoints.
- No compromised issuer private keys or captured credentials in the repository, tests, fixtures, or logs.
- Local test CA is the default. External certificate issuer mode is experimental and requires operator-provided credentials.
- DNS logging and prewarming must be asynchronous and must not delay DNS responses. Deduplicate jobs per normalized hostname and certificate profile; TLS SNI lookup is the fallback.
- Maintain explicit separation between DNS redirection, TLS certificate selection, protocol parsing, capture and emulation.
- Avoid expanding access to non-IoT clients or unconstrained wildcard issuance.
- Preserve certificate-key permissions, issuer validity checks, and request-header redaction.
- Do not modify firewall, DHCP, VLAN, or host DNS configuration automatically.
- Design for offline functionality; no external telemetry.

## Working method
1. Inspect implementation and tests before changing code.
2. Summarize the specific next vertical slice and its acceptance criteria.
3. Implement it with tests and update `README.md` for changed behavior.
4. Run `pytest -q`, and report results and any untested assumptions.
5. Do not claim physical-device or eMudhra compatibility without explicit tests.

See `CODEX_HANDOFF.md` for prioritized follow-up work.
