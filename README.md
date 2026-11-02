# JIT CA — DNS-prewarmed TLS cloud emulator (POC)

An intentionally narrow **working vertical slice** of the JIT CA design:

`DNS A/AAAA query → async cert prewarm → persistent cache → TLS SNI certificate selection → observe request → fixture/backend/empty response → close connection`

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

DNS A answers default to the service's TLS bind address. For a wildcard bind (`0.0.0.0`), the service uses the local interface address selected by the route to the DNS client, without sending a probe packet. Set `network.redirect_ipv4` to override this, especially behind NAT or container port mappings: the service cannot infer the host's externally reachable address. AAAA remains NODATA.
- **Certificate worker:** Single process, queue-based prewarming; deduplicates pending hostname jobs and uses a lock around issuance. Certs survive restarts under `state/certificates/`.
- **Cache validation:** Cached leaves must match their private key, issuer signature, exact hostname and current validity window. Renewal begins within the last tenth of the leaf validity window (at most one day); issuer-limited leaves are reused until expiry when renewal cannot extend their lifetime. Issuer-chain validity is checked on every lookup, including cached TLS contexts.
- **TLS server:** TCP/18443. `SSLContext.sni_callback` selects a prewarmed certificate or signs a leaf during the handshake on cache miss. SNI must match an explicitly configured hostname. Unknown SNI aborts the handshake.
- **Issuer:** `local` mode creates a demo P-256 CA with `keyCertSign` and CA extensions, then RSA-2048 leafs by default. `external` loads your own issuer certificate/key and optional ordered chain. Certificate expiration is limited by issuer-chain `notAfter`. This is not a publicly trusted CA.
- **Emulator:** After TLS, read and log one HTTP/1.1 request, select a hostname/path rule, send its response, then close the connection. With no matching rule, return an empty **204 No Content**. HTTP Host must match TLS SNI. No forwarding happens unless a rule explicitly sets `proxy_pass`.
- **Capture:** `state/events.jsonl` records DNS observations, issuance, TLS selection, HTTP method/path/status, negotiated TLS version/cipher, body SHA-256 and a **redacted JSON preview**. Authorization and cookie headers are redacted. Raw binary bodies are deliberately not saved.

Network handlers and the certificate worker enqueue observations in memory; a dedicated writer serializes and appends them to JSONL. Slow disk writes do not hold up DNS replies or TLS selection. Events become visible asynchronously, and graceful shutdown flushes the queue. A writer failure is reported as an error during shutdown. The queue is currently unbounded, so prolonged slow storage can increase memory use; this remains a lab POC rather than a high-volume capture service.

### Service lifecycle

`stop()` stops accepting requests, waits for active DNS/TLS handlers, drains queued certificate jobs, then writes the final `service_stopped` event and closes the log. TLS request streams and sockets are closed after both successful requests and failed handshakes. Failed construction or partial startup releases listeners and workers already created. Stopping before startup and repeated stops are safe; restarting requires a new service instance.

Shutdown waits for active work rather than abandoning threads after a fixed deadline. TLS socket operations retain the existing eight-second timeout, but signing and storage operations have no forced shutdown timeout. Use graceful shutdown to preserve queued observations; terminating the process abruptly can lose events still in memory.

## Example configuration

See [`config.example.toml`](config.example.toml). Change only the endpoint hostname(s) and static response fixtures to emulate different services. Every hostname must be explicitly listed: no wildcard or unconstrained certificate issuance.

Hostnames normalize case, internationalized names (IDNA), and a single trailing DNS dot. Wildcards, IP literals, whitespace, empty labels and labels with invalid characters or leading/trailing hyphens are rejected.

### HTTP response and backend directives

The existing Python TLS server remains the transport. TOML endpoint and route blocks provide virtual-host and location rules similar to nginx or Apache; they are not nginx/Apache configuration files. Start with only a hostname to observe requests with empty 204 responses, then add fixtures or point selected paths to a local application:

```toml
[http]
max_body_bytes = 65536
backend_timeout_seconds = 5
max_response_bytes = 1048576

[[endpoints]]
hostname = "robot.example.test"

# Exact path, any method unless method is specified.
[[endpoints.routes]]
path = "/status"
method = "GET"
status = 200
content_type = "application/json"
body = '{"connected":true,"mode":"idle"}'
headers = { X-Emulator = "jitca" }

# Forward the original path and query to your explicitly chosen backend.
[[endpoints.routes]]
path_prefix = "/api/"
proxy_pass = "http://127.0.0.1:9000"

# Add another [[endpoints]] block for a different hostname/API.
```

Each route must have exactly one `path` (exact) or `path_prefix` (literal prefix). Matching exact routes win over prefixes, then the longest prefix wins. For the same path match, a specific `method` wins over `"*"` (the default). Query parameters do not affect path matching and are forwarded unchanged to backends. Existing method/path fixtures remain valid. Use a `path_prefix = "/"` static rule for a custom fallback instead of the default 204.

A static rule accepts `status` (200–599), `body`, `content_type` and optional response `headers`. `proxy_pass` accepts an HTTP(S) **origin only**, without a URL path, query or credentials; it forwards the original method, path, query, headers and body to that fixed origin. Combine it with response `headers`, but not static response fields. This supports an arbitrary local API backend without implementing its business logic in JIT CA. HTTPS backend certificates are verified using the system trust store. Backend failures, timeouts and oversized responses return 502. Hop-by-hop headers are removed, backend Host is rewritten, and the client connection closes after the response. Backend bodies are buffered up to `max_response_bytes`; streaming protocols remain unsupported.

`http_request` events record method, hostname, path, repeated query parameters, redacted headers and a redacted JSON body preview before response selection. `http_flow` records the response status and preview. Sensitive query names such as `token`, `password` and `api_key` use the same redaction policy as JSON fields. Arbitrary binary or non-JSON request bodies are hashed but not persisted. Logs are asynchronous as described above.

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

## Actual IoT/VLAN testing

The demo binds to loopback and uses high, unprivileged ports. To test with an enrolled device, you must separately configure an isolated device VLAN, firewall rules, DNS forwarding/overrides, correct advertised gateway IP, and port routing for actual 53/443. These changes are **not** made by this POC. Be aware that if the real endpoint uses a non-HTTP/1.1 protocol, different port, pinned server key, or client certificates, the device won't be supported yet.

For a safe first device test, configure only one explicitly known cloud hostname and exactly one source IP, and preserve ordinary DNS for every other device dependency. Use a dedicated resolver integration or selective policy rather than directing every DNS query to this limited authoritative DNS responder.

## Tests

```bash
pytest -q
```

Integration tests start real UDP/TCP listeners on ephemeral loopback ports and verify **certificate issuance on DNS query, certificate cache reuse, verified TLS handshakes, synthetic responses, SNI fallback, refused hostnames, HTTP host/SNI enforcement, redacted logs, and persisted certs.**

Regression tests also cover slow logging without delayed DNS/TLS responses, shutdown during signing and HTTP handling, failed startup cleanup, failed TLS handshake cleanup, and log writer errors.

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

The HTTP rule dispatcher is separated from the TLS listener. Extend it with stateful local API handlers, and consider **mitmproxy** as an optional HTTP/TLS transport after confirming its certificate-store injection API permits DNS prewarming. Deploy DNS observation through CoreDNS (or a local resolver plugin) so non-intercepted names resolve normally.

The POC establishes the critical sequencing claim: DNS prewarming can produce a certificate **before** the device's TLS `ClientHello`, and SNI can select that certificate **without** generating it during the handshake.
