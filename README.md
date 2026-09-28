# globalprotect-cpp

# Opt-in switches (all lenient behavior is OFF by default)

| Switch | Effect | Default |
|---|---|---|
| `--ignore-tls-errors` | Accept gateway certs that fail validation (tunnel + HTTP client). Every such acceptance is logged with the failure reason. | off |
| `--pin-cert <sha256-hex>` | Require the gateway leaf cert to match this fingerprint *in addition to* chain validation. | unset |
| `--ca-bundle <path>` | Verify against this PEM bundle instead of system paths (fail closed if unreadable). | unset |
| `--allow-remote-callback` | Permit the auth page server to bind a non-loopback address. | off |
| `--allow-redirect-host <host>` | Add host to the redirect allowlist (repeatable). | empty (any http/https host) |
| `--max-callback-payload <bytes>` | Callback payload cap (default 1 MiB). | 1048576 |
| `--callback-timeout-ms <ms>` | Overall callback deadline (default 300000). | 300000 |
| `--http-connect-timeout-s` / `--http-total-timeout-s` | HTTP timeouts (defaults 10/60 s). | 10 / 60 |
| `--max-http-response <bytes>` | HTTP response cap (default 16 MiB). | 16777216 |
| `--allow-insecure-key-file` | Accept a service key file with group/other permission bits. | off |
| `--check-crl` | **Strictening** (not leniency): require a valid, unexpired CRL for every non-root certificate in the chain; chains without one fail closed. | off |
| `--crl-bundle <path>` | Load CRLs from this PEM file for `--check-crl` (otherwise only CRLs already in the trust store are used). | unset |

The last two rows *strengthen* validation; they are listed here because they
are likewise opt-in and off by default. There is deliberately **no** switch to
disable the callback/auth-server token,
the payload caps, the timeouts, or log redaction: those are not "lenient
behavior", they are the baseline.

`SecurityOptions::describe_policy()` returns a human-readable list of every
non-default setting; call it at startup and log the result so any weakening
is visible in the audit trail (the demo does this).

## Build & test

```sh
cmake -B build -G Ninja            # requires: g++ >= 11, OpenSSL dev, libcurl dev
ninja -C build
ctest --test-dir build --output-on-failure
./build/gp_auth_demo               # end-to-end browser-auth flow simulation
./build/gpclient --help            # the end-to-end client (Wave H)
```

## Formatting

Style is defined in `.clang-format` (Google-based, 4-space indent, 100-column
limit). Apply it across the tree with:

```sh
clang-format -i apps/*.cpp examples/*.cpp include/gp/*.h src/*.{cpp,h} tests/*.{cpp,h}
```

Check without writing: `clang-format -n` on the same glob. Tested with
clang-format 23 (the config uses the `UseTab` key, which older releases call
`UseTabForIndent`).

## Layout

```
include/gp/  public headers (options, cert policy, auth server, callback
             listener, secrets, service key, http client, cookie store,
             html utils, ws, aead, json/xml parsers, service daemon,
             gateway client, tunnel client, client flow)
src/         implementation + internal POSIX socket helpers (net_common.*)
tests/       one binary per area + tiny assertion framework (test_framework.h)
examples/    gp_auth_demo — wires the whole flow together
apps/        gpclient — end-to-end client binary (Wave H)
```

## Notes & limitations

- The cert policy is exercised against in-memory generated certificates
  (RSA-2048; this machine's OpenSSL build has a broken EC keygen path, which
  is why the test factory avoids it). CRL checking **is** implemented
  (`--check-crl` enables `X509_V_FLAG_CRL_CHECK`; see the tunnel layer
  section); because the same OpenSSL build also has a broken
  `X509_CRL_sign`, the CRL test helper builds its test CRLs with a manual
  DER construction. OCSP checking remains out of scope.
- No tunnel data-plane backend is compiled in this build. Upstream
  libopenconnect already speaks GlobalProtect; the reference project
  (`yuezk/GlobalProtect-openconnect`, public) layers seven small patches on
  top (app/OS version knobs, HIP-script arguments, session-metadata getters —
  see `implementation.plan.md` §5.2). Building and wrapping that patched
  library is deferred work, not a missing dependency. `gpclient` therefore
  authenticates, obtains the tunnel endpoint, and keeps the session alive;
  with `--no-tunnel` it stops right after the endpoint is obtained. A
  production build injects a `TunnelTransport` implementation (see the tunnel
  layer section) — the security policy around it is fully implemented and
  tested either way.
- `gp::http::HttpClient` uses libcurl easy handles per call; a pooled/multi
  interface can be added without changing the security properties (timeouts,
  caps, and TLS verification are configured per handle).

## Local service daemon (`gp::service::ServiceDaemon`)

The loopback WS/AEAD service that `gpservice` exposed in the Rust client is
implemented as part of this core:

- Binds **127.0.0.1 only** — there is no configuration path to any other
  address; port 0 = ephemeral, actual port reported via `port()`.
- `GET /health` → `200 {"status":"ok"}` (plain HTTP liveness check).
- `GET /ws` → RFC 6455 upgrade: validates `Sec-WebSocket-Key`, replies with
  the correct `Sec-WebSocket-Accept`; missing/invalid headers → 400.
- Every WS message is AEAD-sealed: `12-byte nonce || ciphertext || 16-byte
  tag` (ChaCha20-Poly1305, key from `ServiceKey`). Replies are sealed the
  same way with a fresh random nonce. A message that fails authentication
  ends the session with no reply (fail closed).
- Caps: concurrent connections, per-connection lifetime (SO_RCVTIMEO), max
  message size (oversized → Close frame + disconnect), 16 MiB frame cap.
- `<dir>/gpservice.lock` holds `pid:port`, written 0600 with post-write mode
  verification (L-2) and removed on clean shutdown.

**Scope boundaries.** The daemon acknowledges commands (`health`,
`install_gui`) and echoes only JSON-escaped, safe data — client-supplied
strings are escaped before being embedded in replies. It performs **no real
GUI install side effects** (proprietary payload handling stays out of scope)
and has **no tunnel data plane**. The gateway API client it pairs with is
implemented below (`gp::gateway::GatewayClient`).

## Gateway API client (`gp::gateway::GatewayClient`)

The browser-less GlobalProtect portal flow, driven over the existing
`HttpClient` (timeouts + size caps apply), `cookies::Store` (0700/0600
enforced persistence), and the strict XML parser:

1. **prelogin** — `GET /sslvpnd/prelogin.xml?server=<host>`; strict-XML
   `<prelogin><session_id>…</session_id></prelogin>` (DOCTYPE rejected, so no
   XXE); IKEY cookie ingested from Set-Cookie. Fails closed on any parse
   error, non-200, or missing/empty session id.
2. **login** — `GET /sslvpn-login` form discovery, then POST of the form's
   hidden fields + `username`/`password` (URL-encoded) to its action.
   Redirects are followed **manually** so cookies set on intermediate hops
   are ingested before the next request; after the credential POST, redirects
   are followed with GET so the password is transmitted exactly once.
3. **connect** — `GET /portal/index.html?server=<host>&IKEY=<session_id>`,
   parse the returned form, POST its hidden fields to the action. The tunnel
   endpoint comes from the response's `Location` header (preferred) or a
   `<form>` action in the 200 body.
4. **extend_session** — re-POSTs the saved portal form to renew the session
   TTL; 2xx/3xx counts as renewed.

Security properties:

- Redirect `Location` values must stay on the gateway origin (root-relative,
  or absolute with an identical scheme+host). Foreign hosts, protocol-relative
  `//host`, and any other scheme fail closed — session cookies are never sent
  to third parties.
- Forms are parsed by a strict extractor: NUL bytes, size overflow, non-POST
  methods (credentials would end up in the URL), non-root-relative actions
  (`javascript:`, absolute URLs, …), and CR/LF/control characters in actions
  or hidden values are all rejected. Only `type=hidden` inputs inside the
  `<form>` element are collected; attribute entities are decoded.
- Set-Cookie values are parsed per RFC 6265 (Domain/Path/Expires/Max-Age/
  Secure/HttpOnly, host-only default) and control characters in names/values
  are rejected, so re-emitted `Cookie:` headers cannot inject other headers.
- Credentials appear only in the login POST body; error strings never contain
  username or password, and gateway-provided response bodies are not echoed
  into errors (H-3/M-3 redaction discipline).

**Scope boundaries.** The client authenticates and obtains the tunnel
endpoint; it does **not** implement the IPsec/DTLS data plane. All tests run
against a local loopback fixture gateway — real-gateway validation (including
the final-endpoint extraction shapes) is still pending, as with the rest of
this project. `GatewayConfig::connect_extra_fields` is an escape hatch for
gateways whose portal form requires parameters beyond its hidden inputs.

## Tunnel layer (`gp::tunnel`)

The security-relevant surface of the GlobalProtect tunnel data plane, decoupled
from the actual backend. Upstream libopenconnect already speaks GlobalProtect;
the reference project runs it with seven small public patches (see
`implementation.plan.md` §5.2). This module therefore implements and
unit-tests everything that is security-relevant **independent** of the
backend:

- **Endpoint validation** (`validate_tunnel_config`): https required (http only
  for `127.0.0.1` test servers), no embedded credentials, no control
  characters, proto must be `ipsec` or `dtls`. All failures are closed.
- **`CertPolicyCallback`** — the tunnel-level fix for finding C-1. A backend
  MUST route every presented certificate through it (the exact function a fixed
  OpenConnect `validate_peer_cert()` would call). The old shim returned "accept"
  unconditionally; here the full `SecurityOptions` policy applies — strict by
  default, optional pinning, audited opt-in — and every decision is recorded in
  an audit trail (`TunnelClient::cert_decisions()`). A backend that cannot
  enforce this is simply not built in, never silently weakened.
- **`SessionMetadata`** — a safe C++ port of the reference project's patch 0005
  (user / user-expires extraction). The audit flagged an apparent
  uninitialized-read there (verified non-issue); the port keeps that property
  explicit: the expires field is only read when at least one of the two
  attribute lookups succeeded, and parsing goes through the strict XML parser
  (DOCTYPE rejected ⇒ no XXE, size/depth capped). A malformed metadata document
  surfaces via `metadata_error()` without failing the connect.
- **CRL checking**: with `--check-crl`, the verifier sets
  `X509_V_FLAG_CRL_CHECK` so every non-root certificate in the chain needs a
  valid, unexpired CRL (loaded from `--crl-bundle` when given); chains without
  one fail closed. This applies to tunnel TLS via the same verifier the
  callback uses.

**Scope boundaries.** The production backend wraps (patched) libopenconnect and
implements `TunnelTransport`; it is an integration seam, compiled in only when
the library is available. Tests inject fakes, so the whole policy layer is
exercised without any tunnel dependency: `test_tunnel_client` covers endpoint
validation, metadata parsing (both expires attribute variants, DOCTYPE/size
rejection, missing-attribute safety), cert-callback strict/pin/opt-in behavior,
and client connect/reject/double-connect/RAII/concurrency.

## End-to-end client flow (`gp::client`) and `gpclient`

The complete gpclient flow as a library (`ClientFlow`) plus the
`apps/gpclient` binary. It composes every layer above: posture → gateway API →
tunnel policy → session keep-alive.

Direct-credentials flow:

```
gpclient --user alice --password-on-stdin        (password = one line on stdin)
  |
  v
posture check            optional external program; non-zero exit stops the
  |                      flow BEFORE any credential or session traffic
  v
prelogin                 GET /sslvpnd/prelogin.xml -> session id + IKEY cookie
  |
  v
login                    form discovery, then POST of credentials (sent exactly
  |                      once; redirects followed manually so intermediate
  |                      Set-Cookie headers are ingested first)
  v
connect                  portal form POST -> tunnel endpoint from Location
  |
  v
tunnel                   TunnelClient: cert policy on every presented cert
  |                      (no backend compiled in this build: explicit error,
  |                      or stop early with --no-tunnel)
  v
session extension loop   re-POSTs the saved portal form every
                         --extend-interval-s until Ctrl-C; RAII teardown
```

Browser/IdP-auth flow (`--browser-auth`, no credentials involved):

```
gpclient --browser-auth
  |
  +-> prelogin (as above)
  +-> start CallbackListener   127.0.0.1, one-shot token path (H-1)
  +-> start AuthServer         local page, escaped HTML, validated redirect (H-2)
  +-> [optional] --gui-program GUI host; its URL is delivered on stdin (H-3)
  |
  v
user authenticates in the browser/IdP; the GP plugin POSTs the payload to the
one-shot callback URL (the token path is the only secret; wrong path -> 404
without consuming the one-shot)
  |
  v
payload must carry the "globalprotectcallback:" marker, else rejected
  |
  v
saml_login(payload)      POSTed exactly once as a single form field to
  |                      --callback-return-path; same-origin redirect policy;
  |                      payload never appears in error strings
  v
connect -> tunnel -> session extension loop (same tail as the direct flow)
```

Security properties:

- Credentials come from stdin or a 0600 file, **never argv** (H-3); the
  password is read once and never copied into error strings.
- The browser-auth branch reuses the hardened one-shot callback listener and
  auth page server; the optional GUI host receives its URL on stdin.
- Posture failure is fail-closed before any gateway traffic.
- No static state: `ClientFlow` owns everything, so concurrent flows are safe.
- `--verbose` (or `-v`) traces the whole process to stderr — stage transitions,
  every HTTP hop (method, path, status, byte count), cookie names, certificate
  decisions, session renewals. Trace lines are **metadata only** (M-3): never
  credentials, cookie values, query strings carrying session tokens, or
  callback payloads; `test_client_flow` enforces this for both auth flows.

**Scope boundaries.** `gpclient` authenticates, obtains the tunnel endpoint,
and keeps the portal session alive; it does not implement the IPsec/DTLS data
plane (see the tunnel layer section for the seam). All tests run against a
local loopback fixture gateway: `test_client_flow` covers both flows end to
end, credential handling (stdin/file/argv-refusal), posture fail-closed,
payload marker rejection, cookie forwarding to the tunnel endpoint,
`--no-tunnel` mode, and M-3 redaction of the `--verbose` trace.


