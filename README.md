# JIT CA — DNS-prewarmed TLS cloud emulator (POC)

An intentionally narrow **working vertical slice** of the JIT CA design:

`DNS A/AAAA query → async cert prewarm → persistent cache → TLS SNI certificate selection → observe request → fixture/backend/empty response → close connection`

Requires Python **3.11+** and `cryptography`. All code is Python; there are no shell dependencies except optional `openssl` for inspection. Uses a **newly generated local test CA** by default. No compromised private keys are packaged or downloaded.

## Run locally

The upstream [emudrahahahahaha](https://github.com/Fluepke/emudrahahahahaha) repository is pinned as a Git submodule at `third_party/emudrahahahahaha`, with `main` configured as its update branch. Initialize it after cloning:

```bash
git submodule update --init third_party/emudrahahahahaha
```

The submodule is available for integration work; JIT CA does not load or execute it automatically.

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

The image's entrypoint (`docker/entrypoint.sh`) builds the jitca config from `JITCA_*` environment variables, imports operator CA pairs from the CA volume with `scripts/discover-issuers.sh`, then runs `jitca serve`. The generated config is `config.toml` in `JITCA_CONFIG_DIR` (default `/state`); the examples below use that path. run other subcommands with e.g. `docker compose exec jitca jitca --config /state/config.toml observed`.

| Variable | Meaning (default) |
|---|---|
| `JITCA_ENDPOINTS` | comma/space separated hostnames to serve as explicit endpoints (none) |
| `JITCA_EXTRA_CONFIG` | TOML file appended verbatim, for endpoints with routes or `proxy_pass` (`compose.yaml` sets `/app/docker/robot-demo.toml`) |
| `JITCA_REDIRECT_IPV4` | address DNS answers with; required for answer-all (compose: `127.0.0.1`; set it to the host's LAN address to serve devices) |
| `JITCA_ALLOWED_CLIENTS` | comma/space separated CIDRs (`127.0.0.1/32`; the compose files use the same default) |
| `JITCA_DNS_ANSWER_ALL` | `true` answers every A query with the redirect address (`false`; compose: `true`) |
| `JITCA_DEFAULT_ENDPOINT` / `JITCA_DEFAULT_MAX_HOSTNAMES` | default-allow endpoint and its cap (`false` / 100; compose: `true` / 200) |
| `JITCA_LEAF_KEY`, `JITCA_LEAF_DAYS` | leaf key type and validity (`rsa2048`, 30) |
| `JITCA_DEFAULT_ISSUER` | CA subject substring; needed when the CA volume holds more than one CA |
| `JITCA_LOG_STDOUT` | also print each event as a JSON line to stdout (`false`; local deployment: `true`) |
| `JITCA_CAPTURE_BODIES` (+ `_MAX_BODY_BYTES`, `_MAX_FILES`, `_REDACT`) | raw body capture to `<state>/captures` (`false`; local deployment: `true`) |
| `JITCA_CONFIG_DIR` | where `config.toml` and the stamp live (default: the state dir) |

Values are validated (hostnames, CIDRs, IPv4, booleans) before they reach the config, and a bad value aborts startup.

**Config persistence and reconciliation:** the config and a stamp file (`.entrypoint-stamp`) persist in `JITCA_CONFIG_DIR`. The config is regenerated (previous copy saved as `config.toml.bak`) only when there is none, the `JITCA_*` environment changed (including the contents of `JITCA_EXTRA_CONFIG`), or `JITCA_REGENERATE_CONFIG=1`; otherwise your manual edits are kept. On every start the certificate entries (`mode`, `ca_dir`, `default_issuer` and the staged copies in `<state>/issuers`) are checked against the CA volume. If the volume has CA pairs the config doesn't reference, its pairs changed since the config was built, or the staged copies were altered or removed, the entries are deleted and rebuilt. If the volume has become empty, they are reset to the local demo CA. Nothing else in the config is touched. Compose reads each variable from your shell or `.env` first, so `JITCA_REDIRECT_IPV4=192.0.2.10 docker compose up -d` overrides the default.

**Local deployment:** `local_deployment/compose.yaml` is a self-contained variant. `config/` (generated config + stamp) and `state/` (certificates, events, captures, staged issuers) are bind mounts next to the compose file, and the CA pairs come from an external named volume, `ca-src-private`, mounted read-only (create it with `docker volume create ca-src-private` and copy the `<stem>.pem`/`<stem>.key` pairs in, as in the CA volume example below). It runs as your host uid/gid (`LOCAL_UID`/`LOCAL_GID`, default 1000) so the bind mounts stay writable, and builds from the repo root. Copy `local_deployment/.env.example` to `local_deployment/.env` and uncomment what you need (the defaults bind loopback only); `.env`, `config/`, `state/` and `ca-src/` are git-ignored. Start it with `docker compose -f local_deployment/compose.yaml up -d --build`.

**CA volume:** the root compose mounts the named volume `ca-cert` read-only at `/ca-src`. Put `<stem>.pem`/`<stem>.key` pairs in it (readable by uid 10001). On start the entrypoint clears `/state/issuers`, keeps only pairs OpenSSL reports as `SSL server CA : Yes`, copies them there mode `0600` and switches to `directory` mode. An empty volume means the local demo CA. If the volume has `.pem` files but none is a usable CA, startup fails rather than silently falling back to the demo CA. For example:

```bash
docker run --rm -v jit-ca-codex_ca-cert:/ca -v "$PWD/third_party/emudrahahahahaha:/src:ro" alpine sh -c 'cp /src/*.pem /src/*.key /ca/ && chown 10001 /ca/*'
```

Compose publishes on loopback only by default (host ports 15353/udp and 18443/tcp), and uses named volumes for state and CAs. To serve devices set `JITCA_BIND_ADDRESS` to the host's LAN address, `JITCA_DNS_PORT=53` and `JITCA_TLS_PORT=443`, plus `JITCA_REDIRECT_IPV4` and `JITCA_ALLOWED_CLIENTS`; `local_deployment/.env.example` lists every variable. `demo.py` expects the CA file in local `./state`, so use the Python path for the full demo, or copy the demo CA from the container using `docker compose cp jitca:/state/certificates/demo-root.crt ./demo-root.crt` and adapt the client CA path.

## How it works

- **DNS:** UDP/15353. A query for an explicitly allowlisted endpoint gets the configured gateway IPv4 address, but the reply is held until the leaf certificate for that hostname is actually issued (or confirmed already cached) — the signing happens synchronously in the DNS handler thread before the UDP response goes out. This guarantees a client that proceeds straight from the A answer to a TLS `ClientHello` never hits a signing cache-miss during the handshake. AAAA queries still get NODATA (no IPv6 support in the POC) and only queue nonblocking prewarming, since no certificate is needed for an empty answer. Other hostnames get DNS `REFUSED`; **this is not a general DNS resolver or forwarder**. Never configure it as the household's default resolver.

DNS A answers default to the service's TLS bind address. For a wildcard bind (`0.0.0.0`), the service uses the local interface address selected by the route to the DNS client, without sending a probe packet. Set `network.redirect_ipv4` to override this, especially behind NAT or container port mappings: the service cannot infer the host's externally reachable address. AAAA remains NODATA.

**Answer-all mode (opt-in):** set `network.dns_answer_all = true` (requires a concrete `network.redirect_ipv4`) to answer every `A` query from an allowed client with that address instead of `REFUSED`; other query types get NODATA. This lets a device that uses jit-ca as its resolver send all of its names to this host, but it also means jit-ca is that device's *only* source of real addresses, so nothing else resolves. Catch-all answers never issue certificates (only explicit `[[endpoints]]` are signed), so TLS and HTTP for non-endpoint names are not yet served: unknown SNI still aborts and plain HTTP is served only if the opt-in `[plain_http]` listener is enabled. Names that are not valid hostnames (for example underscore labels) are still dropped. Restrict `allowed_clients` to the enrolled device addresses.

**Selective DNS forwarding (opt-in):** add a `[dns_forward]` table with `upstream` (an IP address, e.g. `"192.168.88.2"`), optional `port` (default 53), optional `timeout_seconds` (default 2) and a non-empty `hostnames` list. A query from an allowed client for one of those exact hostnames (any record type) is relayed over UDP to the upstream resolver and its reply is returned unchanged, so the device gets the real address. No certificate is issued for forwarded names, and they must not also be `[[endpoints]]` (rejected at load). Other names behave as before, including `dns_answer_all`; forwarding takes precedence over it. Upstream timeout, I/O error or a reply with a mismatched ID returns `SERVFAIL`. Events are `dns_query` with `action = "forward"` (or `"forward_failed"`), `upstream`, `rcode`, `reply_bytes`, `truncated` and `answers`: the upstream's answer records as `{name, type, ttl, data}` (A, AAAA, CNAME, NS, PTR and MX decoded; other types as truncated hex; at most 50 records). If the reply cannot be parsed it is still relayed untouched and `answers_error` explains why. A `forward_failed` event has `error` instead. Limits: UDP only (no TCP fallback for truncated replies), exact names only (no wildcards/suffixes), no caching. The upstream is not a general forwarder: only whitelisted names are ever sent to it.

**NTP responder (opt-in):** add an `[ntp]` table (optional `port`, default 123; `host`, default `network.dns_host`; `stratum`, default 2) to answer SNTP client requests over UDP with this host's system clock. Only `network.allowed_clients` are answered; other sources are logged as `ntp_denied` and ignored. Client-mode packets (versions 1-4) get a 48-byte server reply (`ntp_query` event); anything else is dropped (`ntp_invalid`). This is a minimal SNTP responder: no authentication, no NTP extensions, no association with an upstream time source, and it reports itself as synchronized, so the host clock must already be correct. Port 123 needs root or `CAP_NET_BIND_SERVICE`; in a container publish `123/udp` and set the port to match. It is useful for devices whose clock must be right for TLS certificate validity checks.

**Plain HTTP listener (opt-in):** add a `[plain_http]` table (optional `port`, default 80; `host`, default `network.tls_host`) to accept cleartext HTTP/1.1 over TCP. It is the capture point for devices that talk plain HTTP: the same one-request-per-connection parser, `[[endpoints]]`/`[default_endpoint]` routes (including `proxy_pass`), `[capture]` body files and `network.allowed_clients` check as the TLS server, with no certificate involved. The virtual host comes from the `Host` header (port stripped). A request for a name with no endpoint (and no default endpoint), an IP-literal `Host`, or no `Host` is still logged and captured (capture files for the latter two use the label `unknown-host`) but only gets an empty `204`. Events are the usual `http_request` and `http_flow`, with `scheme = "http"`, `host_header`, and a `null` `hostname` when the Host header is not a valid DNS name; there are no TLS fields. Denied sources log `http_plain_denied`; malformed requests log `http_plain_error` and get `400`. Enable `[capture]` to save bodies. Port 80 needs root or `CAP_NET_BIND_SERVICE`; in a container listen on a high port and publish it. Cleartext means no confidentiality: use it only on the isolated device network. Still no chunked bodies, keep-alive, WebSockets or HTTP/2.

**Default-allow endpoint (opt-in):** add a `[default_endpoint]` table (optional `max_hostnames`, default 100, and optional `[[default_endpoint.routes]]` using the same keys as endpoint routes) so that any hostname without an explicit `[[endpoints]]` entry is served instead of aborting the handshake. The TLS SNI callback signs a leaf on demand for that name (bounded by `max_hostnames` distinct names per run; past the cap the handshake is denied and logged), and requests are handled by the default routes (no routes means `204`). Events carry `default_endpoint = true`. Pair it with `dns_answer_all` to see everything a device tries to reach over HTTPS. In `directory` mode it needs `certificates.default_issuer`. Only TLS is served unless the opt-in `[plain_http]` listener is enabled, and clients that do not trust your CA will fail the handshake before sending a request (that shows up as `tls_handshake_failed` with `category = client_alert`, not as `http_request`).

**Raw body capture (opt-in):** add a `[capture]` table with `enabled = true` to write every non-empty request and response body to `<state>/captures/`. Files are **unredacted** by default (the point is seeing exactly what a device sent, so tokens and credentials are stored as-is), mode `0600` in a `0700` directory, named `<utc-time>_<seq>_<host>_<request|response>_<sha12>.bin` (the host is a validated DNS name, never request data). `events.jsonl` uses the configured event-redaction policy and gains `request_capture` / `response_capture` fields (`file`, `bytes`, `truncated`, `redacted`) that name the capture file, so events can be correlated with saved bodies. Limits: `max_body_bytes` per body (default 262144, longer bodies are truncated and flagged) and `max_files` (default 1000; the oldest files are deleted past it). `redact = true` instead stores key-name-redacted JSON and skips non-JSON bodies; this is best-effort and misses secrets under unlisted key names or inside strings. Capture write failures are logged as `capture_error` and never affect the reply. Container variables: `JITCA_CAPTURE_BODIES`, `JITCA_CAPTURE_MAX_BODY_BYTES`, `JITCA_CAPTURE_MAX_FILES`, `JITCA_CAPTURE_REDACT`; `local_deployment/compose.yaml` turns it on. Treat `state/captures/` as sensitive: it can hold device credentials in plaintext.

**Event redaction:** set `[logging] redact = false` to preserve Authorization/Cookie headers,
sensitive query values, and request/response JSON preview fields in both `events.jsonl`
and stdout. If omitted, logs inherit `capture.redact` when capture is enabled; without
capture, logs default to redaction. An explicit `logging.redact` overrides that inheritance.
Body-file redaction remains controlled separately by `capture.redact`. The local deployment
already enables raw capture, so its logs now retain credentials by default. Previously,
headers were always redacted regardless of capture settings. Old redacted events cannot
be recovered; the setting affects new requests. Container override: `JITCA_LOG_REDACT=true|false`
(empty/unset inherits). Both it and `JITCA_CAPTURE_REDACT` are exposed in local Compose.
Changing these environment values regenerates config (backed up as `config.toml.bak`);
restore any custom routes, DNS-forwarding, NTP or plain-HTTP sections from that backup if needed.
For manual config edits with unchanged environment, restart the service to reload.

**Events (`state/events.jsonl`, one JSON object per line):** set `logging.stdout = true` (container: `JITCA_LOG_STDOUT=true`) to also print every event, byte for byte the same line, to stdout, so `docker compose logs` shows them. The file is always written; a closed stdout is dropped silently and never affects it. `local_deployment/compose.yaml` turns it on and gives the container a `json-file` log-rotation policy (5 files of 10 MB, compressed) so the Docker log cannot fill the disk. `events.jsonl` itself is not rotated, and the same configured redaction applies in both places.

| Event | When | Notable fields |
|---|---|---|
| `dns_query` | an allowed client's query was handled | `hostname`, `qtype`, `action` (`endpoint`: answered for an explicit endpoint; `catch_all`: answered by answer-all mode; `nodata`: empty answer, e.g. AAAA or other non-A types; `refused`), `intercepted` (kept for compatibility: it only means the name is an explicit endpoint, so it is false for catch-all answers), `catch_all`, `rcode`, `answer`, `cert` (`issued`/`cached`/`error`/null: the certificate step that held the reply), `elapsed_ms` |
| `dns_denied` / `dns_invalid` / `dns_reply_error` | client not in `allowed_clients` / unparseable or invalid-name query / reply could not be sent | `source`, `bytes`; `dns_invalid` also has `qname` (raw name when it parsed but is not a valid hostname) and `error` |
| `cert_prewarmed` / `cert_prewarm_error` | a leaf was issued or confirmed (`new`) / issuance failed | `hostname`, `trigger` (`dns` or `prewarm`), `elapsed_ms`, `error_type`, `error` |
| `tls_certificate_selected` / `tls_cert_error` | certificate chosen during the handshake / failed to get one | `hostname`, `new`, `elapsed_ms`, `error_type`, `error` |
| `tls_sni_denied` | SNI refused (missing, not allowlisted, or default-endpoint cap reached) | `hostname`, `reason` |
| `tls_handshake_failed` | the TLS handshake did not complete | `source`, `sni` (null if the client sent none), `category`, `reason` (OpenSSL), `error_type`, `error`, `elapsed_ms` |
| `tls_or_http_error` | an error after the handshake, while reading the request | `source`, `error` |
| `http_request` / `http_flow` | request received / reply sent | see above |
| `cert_issuers` / `cert_issuer_expiring` | at start: loaded CAs (`mode`, `default_issuer`, per-CA `subject` and `not_after`) / a CA with under 30 days left | `issuer`, `days_left` |

`tls_handshake_failed.category` is one of `client_alert` (the client aborted, usually `reason = TLSV1_ALERT_UNKNOWN_CA` because it does not trust the CA), `protocol_mismatch` (plain HTTP on the TLS port, no shared protocol or cipher), `sni_rejected` (our refusal; `tls_sni_denied` has the reason), `connection_closed` (the peer hung up, as port scanners and health checks do), `timeout`, or `other`.

Review what was seen with `jitca --config config.toml observed` (per-hostname DNS queries, denied handshakes, request counts, sources and top paths), and `jitca observed --toml` to print `[[endpoints]]` stanzas for hostnames you want to promote to explicit endpoints.

Holding the DNS reply on signing adds latency to that one query: on this POC's local demo CA, issuing an RSA-2048 leaf costs roughly 15-90ms (dominated by RSA key generation), while a P-256 leaf (`leaf_key = "p256"`) costs under a millisecond. A cache hit (hostname already has a valid leaf) adds negligible overhead. Repeated DNS queries for the same hostname while a first issuance is still in flight block on the same certificate-store lock and return as soon as it completes, so they never race into a duplicate issuance.
- **Certificate worker:** A background queue still exists for AAAA-triggered prewarming (dedupes pending hostname jobs, locks around issuance), but the A-record path signs inline on the DNS handler thread instead of going through that queue, so the DNS reply itself is the signal that the certificate is ready. Certs survive restarts under `state/certificates/`.
- **Cache validation:** Cached leaves must match their private key, issuer signature, exact hostname and current validity window. Renewal begins within the last tenth of the leaf validity window (at most one day); issuer-limited leaves are reused until expiry when renewal cannot extend their lifetime. Issuer-chain validity is checked on every lookup, including cached TLS contexts.
- **TLS server:** TCP/18443. `SSLContext.sni_callback` selects a prewarmed certificate or signs a leaf during the handshake on cache miss. SNI must match an explicitly configured hostname. Unknown SNI aborts the handshake.
- **Issuer:** `local` mode creates a demo P-256 CA with `keyCertSign` and CA extensions, then RSA-2048 leafs by default. `external` loads your own issuer certificate/key and optional ordered chain. `directory` loads a flat directory of operator-supplied CA cert/key pairs with no manifest, and picks one CA per endpoint by matching a configured substring against each CA's own certificate subject. Certificate expiration is limited by issuer-chain `notAfter`. This is not a publicly trusted CA.
- **Emulator:** After TLS, read and log one HTTP/1.1 request, select a hostname/path rule, send its response, then close the connection. With no matching rule, return an empty **204 No Content**. HTTP Host must match TLS SNI. No forwarding happens unless a rule explicitly sets `proxy_pass`.
- **Capture:** `state/events.jsonl` records DNS observations, issuance, TLS selection, HTTP method/path/status, negotiated TLS version/cipher, body SHA-256 and a **JSON preview**. Authorization and cookie headers follow the configured event-redaction policy. Raw binary bodies are deliberately not saved.

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

`http_request` events record method, hostname, path, repeated query parameters, headers and a JSON body preview before response selection, following the configured event-redaction policy. `http_flow` records the response status and preview. Sensitive query names such as `token`, `password` and `api_key` use the same redaction policy as JSON fields. Arbitrary binary or non-JSON request bodies are hashed but not persisted. Logs are asynchronous as described above.

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

#### Autodiscovering issuer pairs

`scripts/discover-issuers.sh <source_dir> [config.toml] [ca_dir]` scans a pool of candidate `<stem>.pem`/`<stem>.key` pairs, keeps only the ones OpenSSL's `-purpose` check reports as `SSL server CA : Yes`, copies the matching pairs into the configured `ca_dir` (mode `0600`), and edits the `[certificates]` table of `config.toml` in place to set `mode = "directory"`, `ca_dir`, and (when exactly one issuer is found) `default_issuer` to that CA's common name. It never trusts filenames, requires both `ripgrep` and `openssl` on `PATH`, and leaves `default_issuer`/per-endpoint `issuer` for you to set by hand when more than one issuer is discovered.

The `third_party/emudrahahahahaha` submodule (see [Run locally](#run-locally)) is shaped exactly like this: a flat pool of `<stem>.pem`/`<stem>.key` CA pairs with no manifest. After `git submodule update --init third_party/emudrahahahahaha`, point the script at it directly:

```bash
scripts/discover-issuers.sh third_party/emudrahahahahaha config.toml
```

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
- No general DNS proxy pass-through (only whitelisted names via `[dns_forward]`), TCP/53, DoH or DHCP device attribution.
- No HTTP/2, MQTT, WebSockets, HTTP chunking, or long-lived connections.
- No editable response-rule engine, response-fixture UI, database, or state machines.
- No full stream reassembly/PCAP or replay.
- No per-device trust-store detection, certificate revocation bypass, or pinning bypass.
- No encryption-at-rest for flow data and no multi-process shared cert cache.
- No automatic issuer-chain discovery; externally supplied cross-sign ordering is manual.

### Next integration milestone

The HTTP rule dispatcher is separated from the TLS listener. Extend it with stateful local API handlers, and consider **mitmproxy** as an optional HTTP/TLS transport after confirming its certificate-store injection API permits DNS prewarming. Deploy DNS observation through CoreDNS (or a local resolver plugin) so non-intercepted names resolve normally.

The POC establishes the critical sequencing claim: DNS prewarming can produce a certificate **before** the device's TLS `ClientHello`, and SNI can select that certificate **without** generating it during the handshake.

### Seed the local deployment CA volume

From the repository root, with Python dependencies installed and Docker running:

```bash
git submodule update --init third_party/emudrahahahahaha
python scripts/seed-ca-volume.py
mkdir -p local_deployment/config local_deployment/state
docker compose -f local_deployment/compose.yaml up -d --build --force-recreate
```

The script defaults to the local deployment's `ca-src-private` volume and uid/gid
1000 (override with `--uid`/`--gid` or `LOCAL_UID`/`LOCAL_GID`). It validates every
cert/key pair and verifies parent signatures before touching Docker, then copies
private mode-0600 pairs with the requested ownership. Existing unrelated volume
files are retained; stop the service before reseeding a volume in use. The upstream
files are signing CA certificates, not endpoint leaves. All eight pairs are seeded;
the existing importer selects the six TLS-server CAs and excludes code-signing CAs.
Each `<stem>.pem` contains the signing intermediate followed by its parent root;
directory mode preserves this chain when generating endpoint leaves.

The bundled public `local_deployment/aaa-certificate-services.crt` is the legacy
AAA Certificate Services root from the certifi 2024.08.30 bundle
(https://github.com/certifi/python-certifi/blob/2024.08.30/certifi/cacert.pem),
SHA-256 `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4`.
It is supplied as chain material, not installed into the host trust store.
Use `--chain parents.pem` to add other parent certificates, `--source DIR` for
another source, or `--output-dir DIR` to stage and inspect without Docker.
No network certificate lookup is required. Revocation and real-device acceptance
are not tested by seeding.

Generated leaves use the selected signing CA certificate's exact `notBefore` timestamp.
For EM DV TLS CA - G3B this is May 14, 2025 at 00:00:00 UTC. Expiration remains
bounded by `leaf_days` from issuance and the complete issuer chain's expiration.
Cached leaves with a different start date are regenerated automatically on use
following a service restart; no state deletion is required.
