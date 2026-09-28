# GlobalProtect C++ — Implementation Plan

> **Provenance.** This document was reconstructed on 2026-09-27 after the
> original wave plan was lost in a context compaction. It is grounded in three
> surviving sources of truth: (1) the security findings doc
> `/home/g/security-findings-globalprotect-openconnect.md` — the spec;
> (2) git history — commit `5804d10` "…local service daemon (Wave E) and
> gateway API client (Wave F)"; (3) the code/test inventory and README.
> Waves **E–I** are confirmed by commit messages, README references, and
> session records. The **A–D** boundaries are *inferred* from module
> dependencies and findings priority, because everything up to Wave F was
> committed in a single commit (`5804d10`).

## 1. Goal

Port the secure core of `globalprotect-openconnect` (Palo Alto GlobalProtect
client) to modern C++20, fixing every finding from the security audit along
the way. Deliverables: a testable library (`gp::*`), an end-to-end CLI client
(`gpclient`), a local service daemon, and a small demo — with **no**
GUI/Tauri port.

Spec: `/home/g/security-findings-globalprotect-openconnect.md` (findings C-1,
H-1…H-3, M-1…M-3, L-1…L-3, plus post-audit hardening follow-ups such as
CRL checking).

## 2. Non-goals (explicit)

- No GUI/Tauri layer port; the library is what a future client would link.
- No tunnel data-plane backend in this environment: upstream libopenconnect
  already speaks GlobalProtect, but the reference project's seven small
  public patches (see §5.2) add the app/OS version knobs, HIP-script
  arguments, and session-metadata getters a full client needs; building and
  wrapping that patched library is deferred. `gp::tunnel::TunnelTransport`
  is the integration seam; tests use fakes and `gpclient --no-tunnel`.
- OCSP checking — CRL only (see §5).
- Real-gateway verification — loopback fixture gateway only.

Note: the findings doc's original remediation scope also excluded "the
WebSocket/AEAD service protocol itself"; Waves E–I deliberately expanded past
that boundary (service daemon, gateway client, tunnel layer, end-to-end
client) as new-surface work, not audit remediation.

## 3. Waves

| Wave | Scope | Findings addressed | Status |
|---|---|---|---|
| A | Foundation: test framework, `SecurityOptions`, cert policy core | C-1 (policy engine) | done, committed in `5804d10` *(boundary inferred)* |
| B | Browser-auth flow: callback listener, auth page server, HTML escape, GUI host launcher | H-1, H-2, H-3 | done, committed in `5804d10` *(boundary inferred)* |
| C | Secrets & keys: service key (0600), secret transport | M-1, H-3 | done, committed in `5804d10` *(boundary inferred)* |
| D | HTTP layer & parsers: HTTP client, cookie store, strict XML/JSON, posture | M-2 | done, committed in `5804d10` *(boundary inferred)* |
| E | Local service daemon over WS+AEAD socket | — (new surface) | done, **committed** `5804d10` |
| F | Gateway API client (prelogin/login/connect/session) | — (new surface) | done, **committed** `5804d10` |
| G | Tunnel layer: transport seam, cert-policy callback at tunnel level, session metadata port, CRL checking | C-1 (tunnel level), CRL follow-up | done, **uncommitted** |
| H | End-to-end client flow (`ClientFlow`) + `gpclient` binary | H-3 (credentials never in argv) | done, **uncommitted** |
| I | Test completion (direct unit tests for `gp::ws`, `gp::aead`) + README/diagrams | — | done, **uncommitted** |

### Wave A — Foundation *(inferred boundary)*
- Tiny assertion framework (`tests/test_framework.h`,
  `gp::test::Registry::instance().run_all()`).
- `SecurityOptions` (all lenient behavior opt-in, off by default) and
  `evaluate_peer_cert()` — the C-1 fix: strict-by-default chain validation,
  optional pinning, audited opt-in; replaces the shim's unconditional accept.

### Wave B — Browser-auth flow *(inferred boundary)*
- `CallbackListener`: loopback-only, one-shot token path (H-1); wrong paths
  get 404 without consuming the one-shot; short ≤100 ms accept slices +
  stopped-flag for prompt shutdown.
- `AuthServer`: local page with escaped HTML (H-2), validated redirect, same
  shutdown hardening.
- `html_escape`, `gui` host launcher whose URL is delivered on stdin (H-3).

### Wave C — Secrets & keys *(inferred boundary)*
- `service_key` (M-1): always CSPRNG, all-zero key rejected, key files must
  be 0600 unless `--allow-insecure-key-file`; no compile-time fallback
  constant exists.
- `secret_transport` (H-3): stdin-based secret spawn (refuses argv containing
  secrets), 0600 file/log creation with post-write mode verification,
  `Redactor`; payload caps; secrets never in error strings or logs.

### Wave D — HTTP layer & parsers *(inferred boundary)*
- `http_client` (libcurl) (M-2): connect + total timeouts, response size cap
  enforced in the write callback, http/https-only protocols, TLS verification
  on unless opt-in; header callback strips trailing CRLF (root cause of the
  direct-flow `GPSESSION` loss, fixed in Wave H).
- `cookie_store`: RFC 6265 subset with path matching, `trim_ws()` treating
  `\r\n` as whitespace.
- Strict `xml`/`json` parsers: DOCTYPE rejected (no XXE), size/depth caps
  (M-2), `\uXXXX` surrogate-pair decoding.
- `posture`: external preflight, fail-closed before any gateway traffic.

### Wave E — Local service daemon *(confirmed)*
- `service_daemon` over a local socket using `ws` framing + `aead`
  (ChaCha20-Poly1305); `net_common` POSIX socket helpers; `random`.

### Wave F — Gateway API client *(confirmed)*
- `GatewayClient`: prelogin → login → connect → session extension, manual
  redirect following so intermediate `Set-Cookie` headers are ingested first;
  credentials POSTed exactly once.

### Wave G — Tunnel layer & CRL checking *(uncommitted)*
- `TunnelClient` + `TunnelTransport` seam: endpoint validation (https only,
  no userinfo, ipsec/dtls proto), RAII disconnect, no static state.
- `CertPolicyCallback`: the tunnel-level C-1 fix — every presented cert goes
  through `evaluate_peer_cert` with full policy; decisions recorded in an
  audit trail (`cert_decisions()`).
- `SessionMetadata`: safe port of reference patch 0005 (user/user-expires);
  strict XML, DOCTYPE rejected.
- CRL checking: `--check-crl` sets `X509_V_FLAG_CRL_CHECK`; optional
  `--crl-bundle` PEM file; chains without a valid unexpired CRL fail closed.
- Tests: `test_tunnel_client` (25 cases) + CRL cases in `test_cert_policy`.

### Wave H — Client flow & `gpclient` *(uncommitted)*
- `ClientFlow`: posture → prelogin → login|browser-auth → connect → tunnel →
  session-extension loop; owns all state (concurrent flows safe).
- Credentials from stdin or 0600 file, **never argv** (H-3).
- `apps/gpclient` binary: `--user/--password-on-stdin`,
  `--credentials-file`, `--browser-auth`, `--no-tunnel`, posture + CRL flags.
- Bugs found and fixed while wiring it up:
  - libcurl header lines carry trailing CRLF → last `Set-Cookie` attribute
    became `Path=/\r\n` → `GPSESSION` dropped for `/tunnel/start`. Fixed at
    the root in `http_client::header_cb` + defensive `trim_ws()`.
  - Browser-auth shutdown hang: closing the listener fd does not interrupt a
    blocking `poll()`; fixed with short accept slices + stopped checks.
- Tests: `test_client_flow` (20 cases) against a loopback fixture gateway.

### Wave I — Test completion & documentation *(uncommitted)*
- Direct unit tests for the two components previously covered only indirectly:
  - `test_ws` (13): RFC 6455 accept-key vector, all length forms, masking,
    reserved bits, control-frame limits, truncation, oversized headers,
    multi-frame buffers.
  - `test_aead` (9): seal/open roundtrips, nonce determinism/separation,
    tamper/wrong-key/wrong-nonce rejection, short input, malformed key size.
- README: tunnel-layer and client-flow sections with ASCII flow diagrams for
  both auth flows; `--check-crl`/`--crl-bundle` in the switches table;
  corrected Notes & limitations (CRL implemented, OCSP out of scope, no
  compiled-in tunnel backend).

## 4. Findings → fixes map

| Finding (as audited) | C++ fix | Wave |
|---|---|---|
| C-1 gateway TLS cert validation unconditionally bypassed (full tunnel MITM) | `gp::cert::evaluate_peer_cert` + OpenSSL verifier (chain + hostname/IP, optional SHA-256 pin, CA-bundle override, fail-closed on broken store); blanket accept only via `--ignore-tls-errors`, logged as `INSECURE OPT-IN`; tunnel-level `CertPolicyCallback` with audit trail | A, G |
| H-1 callback listener: unauthenticated local session injection, unbounded read, no timeout | `gp::auth::CallbackListener`: 256-bit token path (constant-time compare, uniform 404), payload cap checked before reading (413), deadline, one-shot, 0600 port file without the token | B |
| H-2 AuthServer serves portal-controlled HTML; Remote mode binds to the LAN | `gp::auth::AuthServer`: locally generated template only (all portal values escaped), redirect validation at startup (scheme/control-char/userinfo/allowlist), loopback-only unless `--allow-remote-callback`, request cap + lifetime deadline | B |
| H-3 sensitive auth material in CLI args + world-readable logs | `gp::secrets`: stdin-based secret spawn (refuses argv containing secrets), 0600 file/log creation with post-write mode verification, `Redactor`; `gpclient` takes credentials from stdin/0600 file; GUI URL delivered on stdin | B, H |
| M-1 hardcoded all-zero service API key in debug builds | `gp::service::ServiceKey`: always CSPRNG, zero-key rejected, key files must be 0600 unless `--allow-insecure-key-file`; no compile-time fallback constant exists | C |
| M-2 no timeouts or size limits on portal/gateway HTTP clients | `gp::http::HttpClient`: connect + total timeouts, response size cap enforced in the curl write callback, http/https-only protocols; strict XML/JSON parsers with size/depth caps | D |
| M-3 log redaction only after first Connect; client-side logs unredacted | `Redactor` + never-log-raw rule (logs carry byte counts, not payloads) | C |
| L-1 FFI robustness gaps (static connection state, unchecked null deref) | RAII ownership, no global static connection state, thread-confined network objects | structural, all |
| L-2 service port discoverable + unauthenticated endpoints (liveness oracle) | all service payloads AEAD-encrypted before sending; key file permissions enforced | E |
| L-3 minor (UDP source-IP probe; one-shot URL probeable via HEAD 200) | loopback-only bind; uniform 404 on wrong path without consuming the one-shot | B |
| CRL checking (post-audit follow-up for the tunnel integration) | `--check-crl` (`X509_V_FLAG_CRL_CHECK`) + optional `--crl-bundle`; chains without a valid unexpired CRL fail closed | G |

## 5. Deferred / out of scope (how to resume)

1. **OCSP checking** — not started; CRL only. To add: extend the verifier
   with an OCSP responder config + `X509_STORE_set_flags(X509_V_FLAG_OCSP_*)`
   and a new opt-in flag, mirroring the CRL path in Wave G.
2. **Tunnel data-plane backend** — *not blocked on patch availability.* The
   reference project is public: `github.com/yuezk/GlobalProtect-openconnect`
   (GPL-3.0). Its OpenConnect integration lives in `crates/openconnect/`: a
   git submodule pinned to upstream master commit
   `0dcdff87db65daf692dc323732831391d595d98d` (2025-11-03, post-MR !619) plus
   seven patches in `crates/openconnect/deps/patches/`, applied by
   `build.rs` with `patch -p1` before an autotools static build:

   | Patch | Effect |
   |---|---|
   | 0001 app-version | `gp_app_version` field + `openconnect_set/get_gp_app_version()`; getconfig sends it (fallback `6.3.0-33`); HIP `APP_VERSION` env var |
   | 0002 user-agent | stops forcing UA `"PAN GlobalProtect"` in GP common headers |
   | 0003 os-version | `gp_os_version` field + set/get; login/getconfig send it (fallback `platname`) |
   | 0004 HIP args | HIP script gets `--client-version/--client-os/--os-version` |
   | 0005 session metadata | parses getconfig `lifetime`, `user-expires(_expires)`, `lifetime-notify-prior/-message`; four new public getters, exported in the symbol map (already ported to C++ as `SessionMetadata`) |
   | 0006 host-id | `gp_host_id` field + set/get; HIP script gets `--host-id` |
   | 0006 debug-log | PRG_DEBUG dump of raw getconfig.esp XML — do **not** port (conflicts with M-3 never-log-payloads) |

   None of the patches implement the GP protocol itself — upstream
   OpenConnect already does; they only add knobs, HIP arguments, and
   metadata exposure.

   **Why the reference project exists at all** — stock OpenConnect has
   shipped the complete GP protocol since 2016–17 (`--protocol=gpst`,
   `gpst.c` © D. Lenski): portal/gateway XML config, username/password +
   client-cert + SSO/SAML browser auth, *both* data planes (SSL/DTLS stream
   tunnel and ESP-over-UDP magic-ICMP probes, `gpst_esp_send_probes`), and
   HIP script invocation. The Rust project is a **product layer** on that
   engine, not a protocol implementation: `gpauth` (SSO/MFA/FIDO2
   orchestration, browser integration, cookie handoff to the privileged
   process via stdin), `gpservice` (background daemon — auto-connect,
   session persistence across CLI invocations, local IPC; the WS+AEAD
   surface our `gp::service` mirrors), a Tauri GUI/tray (paid component),
   the fingerprint/metadata knobs above, and self-contained packaging
   (vendored + patched libopenconnect statically linked via a C shim, so
   end users don't depend on distro libopenconnect versions). The audit's
   critical findings were all in that layer — notably C-1 was in their FFI
   shim, not upstream OpenConnect. Our port is the same layer rebuilt
   securely; the engine seam is exactly where we stop today.

   **Drop-in assessment: a `TunnelTransport` over stock
   libopenconnect (zero patches) satisfies the full interface contract** —
   cookie handoff via stock `openconnect_set_cookie()`, the C-1 cert policy
   via stock `openconnect_set_validate_peer_cert()` wired to
   `CertPolicyCallback`, and `session_metadata_xml()` may return empty
   (metadata is informational; expiration data already comes from our own
   control-plane client). The only patches that could matter against a real
   gateway are 0001/0003 (client fingerprint: stock sends
   `app-version=6.3.0-33` and `os-version=<platname>`; a gateway enforcing a
   minimum client version or version-keyed posture would reject) — if needed,
   reimplement as ~20-line micro-patches rather than adopting the series.
   To resume: clone the repo (`git submodule update
   --init`), build stock libopenconnect at the pinned commit (patches
   optional), implement a `TunnelTransport` wrapping it, and wire it into
   `gpclient` behind a build flag; all surrounding policy is already tested
   via fakes.
3. **Real-gateway verification** — needs live gateway access. Endpoint
   extraction shapes are fixture-tested only today.

## 6. Verification baseline (as of this writing)

- Clean build: 0 warnings, 0 errors (`ninja -C /tmp/gp_build_g`).
- `ctest`: **20/20 suites pass** (~36 s), including `test_ws` (13),
  `test_aead` (9), `test_tunnel_client` (25), `test_client_flow` (20).
- The findings doc's remediation table ("all 9 test suites pass, 52 test
  cases") describes the state at the end of the original core waves; Waves
  E–I grew the suite to the current 20.
- Working tree: Waves G/H/I uncommitted; unrelated `nfs-smb-client` changes
  present in the same repo — commit only `globalprotect-cpp/` paths.

