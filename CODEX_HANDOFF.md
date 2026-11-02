# JIT CA — Handoff from ChatGPT design conversation

## What the user wants
Build a self-hosted **Just-in-Time Certificate Authority** development toolkit for recovering ownership/control of cloud-dependent IoT devices when vendors discontinue support. The desired workflow is:

1. Observe **DNS requests from explicitly enrolled devices** on an isolated device VLAN.
2. Apply selective DNS overrides and trigger **asynchronous certificate-cache prewarming** for approved cloud hostnames.
3. Receive TLS `ClientHello`, select a certificate by SNI (or an unambiguous per-IP mapping), and issue on cache miss if the DNS prewarm has not completed.
4. Terminate TLS using a device-compatible issuer chain where the device's trust configuration permits it.
5. Inspect and persist the resulting application traffic, with redaction and replay support.
6. Interactively synthesize responses and progressively implement a **stateful local cloud emulator**.
7. Export a working emulator as its own deployable project; do not require the original vendor service.

The motivating project is https://github.com/carbon198/roomba-cloud. JIT CA is intended to support this **class** of projects, not just Roombas.

## Existing POC (verified)
The project in this repository is a functional, narrow Python POC:
- UDP DNS listener on unprivileged loopback port 15353. Configured hostnames resolve to a local IPv4 address; queries trigger async prewarm.
- Persistent signed leaf cache; generated local demo CA by default; operator-supplied external issuer option.
- TLS listener on loopback port 18443 with SNI callback selecting prewarmed leaves or signing a leaf on demand.
- Static HTTP/1.1 method+path fixtures and basic JSONL event/flow logging.
- Device/hostname restrictions; redaction of authorization/cookie material in event logs.
- End-to-end tests exercise DNS prewarm, verified TLS, cache hit, SNI fallback, rejection paths, and restart persistence.

**Not implemented**: DNS forwarding for non-intercepted domains, source device identity, production port 53/443 routing, per-device profiles, HTTP/2, MQTT, WebSocket, transparent TCP interception, dynamic response editing, state machines, SQL persistence, external UI, replay, exportable emulator SDK, or real eMudhra/device compatibility validation.

## Important design decisions
- DNS is the **prewarm trigger**; SNI is the **authoritative TLS selector** when available. DNS queries can be cached, absent, or shared between devices, so a handshake-time cache miss path is required.
- Do not synchronously block DNS on signing; use single-flight deduplication for concurrent DNS/TLS issuance.
- DNS TTL and certificate lifetime are independent. `leaf_days` is configurable and issuance must not exceed issuer-chain validity.
- Support multiple chain profiles eventually (local CA, operator-supplied issuer, legacy cross-sign), chosen per enrolled device; do not hardcode a specific CA.
- IoT trust stores vary: a frozen root store is different from explicit leaf/SPKI pinning. Certificates cannot override pinning, mTLS, revocation, or expiration requirements.
- Prefer modular protocol adapters over forcing MQTT/custom TCP into an HTTP-only proxy architecture.
- Keep the application offline-capable, observable, reproducible and self-hosted.

## Next milestones (recommended sequence)

### M1: Harden the initial POC
- Separate network listener, certificate provider, cache, and emulator handler interfaces.
- Strengthen error handling/observability, expand tests for DNS concurrency, prewarm races, wildcard/SNI edge cases, and certificate-chain expiry.
- Build CI workflow for pytest and static checks.

### M2: Production DNS integration
- Support forwarding all non-intercepted queries through existing DNS infrastructure (CoreDNS or pluggable resolver adapter).
- Map DNS requests to enrolled device identities; support selective overrides and device/hostname rules.
- Avoid unintended AAAA response behavior when IPv6 listener is absent.

### M3: TLS/protocol gateway
- Evaluate mitmproxy addon integration to reuse its more capable HTTP/TLS stack while sharing the prewarmed certificate cache.
- If addon integration cannot inject or select cached certs reliably, document limitation and retain a separate termination adapter.
- Add protocol adapter hooks for HTTPS, WebSocket, MQTT-over-TLS, generic TCP.

### M4: Traffic lab and capture
- Add normalized flow representation, request/response artifacts and configurable redaction.
- Add operator-defined response rules, templated fixtures, controlled replay and experiment/version tracking.

### M5: Cloud emulator SDK
- Define an emulator manifest and Python handler API with durable state machines.
- Export runnable stand-alone emulator packages, optionally with Home Assistant integration.

## First Codex task suggestion
"Read README.md, AGENTS.md, and CODEX_HANDOFF.md. Run the tests. Audit the current DNS prewarming and TLS SNI certificate-selection path for correctness, concurrency races, certificate expiry, hostname/allowlist handling and insecure defaults. Implement the highest-priority fixes with integration tests, without broadening default network access. Report results, open design questions, and the recommended next vertical slice."
