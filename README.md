# JIT CA — DNS-prewarmed TLS cloud emulator (POC)

An intentionally narrow **working vertical slice** of the JIT CA design:

`DNS A/AAAA query → async cert prewarm → persistent cache → TLS SNI certificate selection → static local HTTP emulator → JSONL event log`

Requires Python **3.11+** and `cryptography`. All code is Python; there are no shell dependencies except optional `openssl` for inspection. Uses a **newly generated local test CA** by default. No compromised private keys are packaged or downloaded.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp config.example.toml config.toml
jitca --config config.toml serve
```

In another terminal:

```bash
. .venv/bin/activate
python demo.py
jitca --config config.toml issuer
jitca --config config.toml certs
jitca --config config.toml events --tail 30
pytest -q
```

Expected demo response: `DNS A: 127.0.0.1`, then `TLS: TLSv1.3` (or TLSv1.2), `HTTP/1.1 200 OK` and JSON containing `"source":"jitca"`.

After the first run, verify the issued leaf:

```bash
find state/certificates -name fullchain.pem -print
openssl x509 -in "$(find state/certificates -name fullchain.pem | head -1)" \
  -noout -subject -issuer -dates -ext subjectAltName
```

Run with Docker (optional; requires Docker Engine/Compose):

```bash
docker compose up --build
```

Compose publishes **loopback-only** ports and uses a named state volume. `demo.py` expects the CA file in local `./state`, so use the Python path for the full demo, or copy the test CA certificate from the container using `docker compose cp jitca:/state/certificates/demo-root.crt ./demo-root.crt` and adapt the client CA path.

## How it works

- **DNS:** UDP/15353. A query for an explicitly allowlisted endpoint gets the configured gateway IPv4 address and queues one nonblocking issuance request. AAAA queries get NODATA (no IPv6 support in the POC) and still queue prewarming. Other hostnames get DNS `REFUSED`; **this is not a general DNS resolver or forwarder**. Never configure it as the household's default resolver.
- **Certificate worker:** Single process, queue-based prewarming; deduplicates pending hostname jobs and uses a lock around issuance. Certs survive restarts under `state/certificates/`.
- **TLS server:** TCP/18443. `SSLContext.sni_callback` selects a prewarmed certificate or signs a leaf during the handshake on cache miss. SNI must match an explicitly configured hostname. Unknown SNI aborts the handshake.
- **Issuer:** `local` mode creates a demo P-256 CA with `keyCertSign` and CA extensions, then RSA-2048 leafs by default. `external` loads your own issuer certificate/key and optional ordered chain. `directory` loads a flat directory of operator-supplied CA cert/key pairs with no manifest, and picks one CA per endpoint by matching a configured substring against each CA's own certificate subject. Certificate expiration is limited by issuer-chain `notAfter`. This is not a publicly trusted CA.
- **Emulator:** HTTP/1.1 with static method/path response mappings. Unknown paths return JSON 404 and are recorded for exploration. HTTP Host must match TLS SNI.
- **Capture:** `state/events.jsonl` records DNS observations, issuance, TLS selection, HTTP method/path/status, negotiated TLS version/cipher, body SHA-256 and a **redacted JSON preview**. Authorization and cookie headers are redacted. Raw binary bodies are deliberately not saved.

## Example configuration

See [`config.example.toml`](config.example.toml). Change only the endpoint hostname(s) and static response fixtures to emulate different services. Every hostname must be explicitly listed: no wildcard or unconstrained certificate issuance.

### External issuer profile (experimental)

The signer accepts an **operator-supplied** intermediate CA and corresponding key:

```toml
[certificates]
mode = "external"
state_dir = "./state"
issuer_cert = "issuer/issuing-intermediate.pem"
issuer_key = "issuer/issuing-intermediate.key"
chain_files = ["issuer/parent-cross-sign.pem"]
leaf_days = 30
leaf_key = "rsa2048"
```

The configured issuer must be currently within its `notBefore`/`notAfter` interval, have CA basic constraints, and match the private key. The chain files are loaded **in the order supplied** and their expiration dates further constrain the leaf's validity. This profile can represent a legacy intermediate and cross-sign but is **not** automatically eMudhra-aware and hasn't been tested against a real compromised chain. When a device has pinned a leaf/SPKI, uses mTLS, or rejects the chain due to revocation, this mechanism cannot make the device accept it.

> Note: Do not copy CA private keys into a repository. This POC keeps raw PEM keys on disk with mode 0600; a production signer would use a separate key management boundary. A CA with broadly trusted legacy roots is **not** safe to expose for general network interception.

### Directory issuer profile (experimental)

For operators holding several **operator-supplied** CA cert/key pairs (for example, distinct DV/OV/EV TLS and OV code-signing issuing CAs across different generations/regions), point at a flat directory with no manifest and no subdirectories:

```
issuer/cas/
  ov-tls-g3c-us.pem
  ov-tls-g3c-us.key
  ev-tls-g3b-nl.pem
  ev-tls-g3b-nl.key
  ... (8 matching .pem/.key pairs total)
```

```toml
[certificates]
mode = "directory"
state_dir = "./state"
ca_dir = "issuer/cas"
default_issuer = "OV TLS"   # substring matched case-insensitively against a CA's subject DN
leaf_days = 30
leaf_key = "rsa2048"

[[endpoints]]
hostname = "robot.example.test"
issuer = "EV TLS"           # per-endpoint override of default_issuer
```

Each `.pem` must have a sibling `.key` of the same filename stem (and vice versa); any orphan file is a configuration error. Filenames are for human reference only — JIT CA reads each CA's **profile from the certificate itself** (subject DN, CA basic constraints, `keyCertSign`) rather than trusting the filename. `default_issuer` and any per-endpoint `issuer` selector must each match **exactly one** CA's subject in the directory; zero or multiple matches is a startup error. Per-endpoint `issuer` is only valid when `certificates.mode = "directory"`. As with the external profile, this does not bypass pinning, mTLS, revocation, or expiry, and is not automatically eMudhra- or vendor-aware.

## Actual IoT/VLAN testing

The demo binds to loopback and uses high, unprivileged ports. To test with an enrolled device, you must separately configure an isolated device VLAN, firewall rules, DNS forwarding/overrides, correct advertised gateway IP, and port routing for actual 53/443. These changes are **not** made by this POC. Be aware that if the real endpoint uses a non-HTTP/1.1 protocol, different port, pinned server key, or client certificates, the device won't be supported yet.

For a safe first device test, configure only one explicitly known cloud hostname and exactly one source IP, and preserve ordinary DNS for every other device dependency. Use a dedicated resolver integration or selective policy rather than directing every DNS query to this limited authoritative DNS responder.

## Tests

```bash
pytest -q
```

Integration tests start real UDP/TCP listeners on ephemeral loopback ports and verify **certificate issuance on DNS query, certificate cache reuse, verified TLS handshakes, synthetic responses, SNI fallback, refused hostnames, HTTP host/SNI enforcement, redacted logs, and persisted certs.**

## Current limitations (deliberate)

This is **not yet a replacement for mitmproxy, Squid, or roomba-cloud**. Specifically:

- No transparent interception/NAT setup or upstream forwarding.
- No DNS proxy pass-through, TCP/53, DoH or DHCP device attribution.
- No HTTP/2, MQTT, WebSockets, HTTP chunking, or long-lived connections.
- No editable response-rule engine, response-fixture UI, database, or state machines.
- No full stream reassembly/PCAP or replay.
- No per-device trust-store detection, certificate revocation bypass, or pinning bypass.
- No encryption-at-rest for flow data and no multi-process shared cert cache.
- No automatic issuer-chain discovery; externally supplied cross-sign ordering is manual.

### Next integration milestone

Replace the static-response handler with a protocol adapter. Add an addon for **mitmproxy** as an optional HTTP/TLS transport, but first confirm that its certificate-store injection API permits DNS prewarming without duplicating mitmproxy's existing eMudhra certificate machinery. Deploy DNS observation through CoreDNS (or a local resolver plugin) so non-intercepted names resolve normally.

The POC establishes the critical sequencing claim: DNS prewarming can produce a certificate **before** the device's TLS `ClientHello`, and SNI can select that certificate **without** generating it during the handshake.
