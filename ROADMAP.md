# JIT CA — Roadmap

This file tracks implementation status at a glance. Update it in the same change set whenever a feature's status changes (see `AGENTS.md`).

## Current implementation status

| Capability | Status |
|---|---|
| DNS A query blocks its reply until the leaf certificate is issued (AAAA queues nonblocking prewarming) | Implemented |
| Persistent certificate cache | Implemented |
| SNI-based certificate selection and fallback issuance | Implemented |
| Local and externally supplied CA signing | Implemented |
| Multiple issuer selection by certificate subject | Implemented |
| Issuer autodiscovery script (`scripts/discover-issuers.sh`, directory CA mode) | Implemented |
| HTTP/1.1 static responses | Implemented |
| HTTP/1.1 forwarding to configured backends | Implemented |
| JSONL request, DNS, certificate-issuance and TLS handshake-failure event logging | Implemented |
| Opt-in DNS answer-all mode (every A query answered with a configured address; no certs for non-endpoint names) | Implemented |
| Default-allow endpoint: on-demand TLS leaf and request logging for unlisted hostnames (capped), `jitca observed` summary | Implemented |
| Container entrypoint: env-driven config generation and CA-volume import via `discover-issuers.sh`, with persistent config reconciled against the CA volume on start | Implemented |
| Optional stdout mirror of the event log, plus Docker log rotation in the local compose | Implemented |
| Local deployment (`local_deployment/`): external CA volume, bind-mounted `config/` and `state/`; validated full-chain seeding script | Implemented |
| Opt-in raw request/response body capture to `state/captures` (private files, size and count caps, optional redaction) | Implemented |
| Selective DNS forwarding: whitelisted exact hostnames relayed over UDP to a configured upstream resolver (`[dns_forward]`) | Implemented |
| General-purpose DNS forwarding (all non-intercepted names, TCP, caching) | Missing |
| Opt-in SNTP responder answering from the host clock (`[ntp]`, allowed clients only) | Implemented |
| Opt-in plain HTTP listener and body capture point (`[plain_http]`; Host-header vhosts, same routes/capture/logging as TLS) | Implemented |
| Automatic VLAN/device identification | Missing |
| HTTP/2, MQTT, WebSockets | Missing |
| Interactive response editing and replay | Missing |
| Stateful cloud-service emulation | Missing |
| Physical-device compatibility testing | Not verified |

## Status definitions
- **Implemented**: code and tests exist and pass (`pytest -q`).
- **Missing**: no implementation exists yet.
- **Not verified**: cannot be claimed true or false without a real-device test; do not mark "Implemented" without one.
