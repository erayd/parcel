# Security Review - Parcel v1.0.7 (kimi-k3)

## Executive Summary

Parcel v1.0.7 (commit `099857c`, tag `v1.0.7`, clean tree) is in excellent security shape. This review found **no CRITICAL, HIGH, or MEDIUM vulnerabilities**. Seven LOW and two INFORMATIONAL findings are recorded. Two LOW are build/tooling hygiene (F63L, F64L); four LOW and two INFORMATIONAL arrived via cross-model exchange and were independently reproduced and confirmed (F60L, F61L, F62L, F65L, F66I, F67I); one further exchanged finding's behaviour was confirmed but its severity is disputed (F59M, rated M by glm-5.3, L here - see Cross-Model Verification).

Finding counts: 0 C / 0 H / 0 M / 7 L / 2 I.

The single most important takeaway: the v1.0.6-era security fixes (anchored VALIDSIG extraction, atomic rate-limiter state, schema hardening, TOTP validation, crossOrigin labelling) are all present, unbypassed, and now backed by adversarial regression tests; the significant new v1.0.7 surfaces (parcelrc whitelist parser, environment hardening, signer revocation, privacy clipboard, HTTP auth, setup script) were all audited and hold up under their stated threat models. The full test suite passes 595/595, and the built chrome/ and firefox/ bundles are byte-identical to src/.

## Trust Model & Attack Surfaces

Components examined: the bootstrap host (`parcel-host`), the main host (`src/parcel-host`), the MV3 service worker (`src/js/agent.js`), the isolated-world content script (`src/js/integration.js`), the MAIN-world shims (`src/js/main-world/shadow.js`, `src/js/main-world/webauthn.js`), the popup UI (`src/js/popup.js`, `src/html/popup.html`), shared modules (`helpers.js`, `plaintext.js`, `schema.js`, `selectors.js`, `targets.js`, `webauthn.js`), the manifest and packaging (`src/manifest.json`, both Makefiles, `src/parcel-setup.sh`, `scripts/`, `example/`, `Dockerfile`), and the test suite (`test/`).

My own structural read of the trust-boundary hierarchy:

1. **The bootstrap host is the root of trust.** It is the only component the browser launches directly. It constrains its own environment (privileged re-exec, environment whitelist, strict-mode PATH/binary vetting), validates parcelrc through a canonical `KEY="value"` whitelist parser rather than sourcing it, and then gates the main host script behind GPG signature verification against `VALID_SIGNERS`, blacklist checks against both primary and subkey fingerprints, and the optional `HOST_HASH` pin. Every failure path is fail-closed with static extension-facing messages.
2. **The main host is the enforcement boundary for the store.** Whitelist evaluation, symlink policy, rate limiting, audit logging, passkey rpId/allowCredentials binding, and the passkey-content backstop all live here, so a fully compromised extension cannot exceed them. Private key material (GPG, passkey) never crosses into the browser; only decryptions of whitelisted non-passkey entries and passkey *signatures* do.
3. **The service worker is a broker, not a boundary.** It enforces a per-port-type action allow-list and per-challenge http-auth token restriction, but correctly assumes it may be compromised and defers real enforcement to the host.
4. **The content script is the origin boundary for fills.** Fill destination origin is validated against the delivering frame's own `window.location.origin` at fill time; passkey ceremony parameters (origin, rpId, crossOrigin) are re-derived in the isolated world, never taken from the page-realm bridge.
5. **The MAIN-world shims are untrusted by design.** Everything arriving over the DOM CustomEvent bridge is schema-validated and re-derived isolated-side; the documented worst case for a forged bridge message is popup annoyance.
6. **The popup is the consent and display surface.** It renders store-controlled data exclusively through `textContent` (no HTML sinks anywhere), keys history per-origin/per-container, and shows the true origin for every consent decision.

## Methodology

- **Model:** kimi-k3 (running as kimi-k3-flex; operational suffix omitted per convention).
- **Date:** 2026-09-12.
- **Tree:** release review at commit `099857c` == tag `v1.0.7`; working tree clean (`git status --porcelain` empty), so the review covers exactly the shipped tree.
- **Documents read in full, in order:** CONSTITUTION.md, SECURITY.md, README.md, security-review/findings.md. No file under `security-review/reviews/` was opened or read. Per §0's naming-convention instruction, directory *names* under `security-review/reviews/` were listed (filenames only, no content) to derive the `kimi-k3` model tag; this is recorded here for honesty.
- **Source examined:** all files listed in Trust Model & Attack Surfaces above, read directly by the main session; the three subagent scopes below were additionally read in full by their respective agents.
- **Subagent allocation (all model kimi-k3-flex, per the review constraints):**
  1. Native host + host-side constitution compliance (`parcel-host`, `src/parcel-host`).
  2. Extension JS + WebAuthn + popup (`src/js/*`, `src/html/popup.html`).
  3. Manifest/build/tests + regression checks (`src/manifest.json`, Makefiles, setup script, `scripts/`, `example/`, `test/`).
  Every subagent finding and regression claim entering this report was independently re-verified by the main session against the code (see Findings and Regression Checks).
- **Tests run:** full suite via the build subagent: prettier --check PASS, eslint PASS, `bash -n` PASS on all shell sources, `node --test` over all 16 suites plus the setup suite: **595/595 pass**. shellcheck was unavailable in the container (noted, non-blocking; `bash -n` covered syntax). The host subagent additionally ran `node --test test/native-host.test.js` (143/143) and the extension subagent ran the browser-side suites (392 tests).
- **Empirical verification beyond the suite (subagent-executed, main-session spot-checked):** live GnuPG 2.4.9 experiment with a malicious-UID key embedding a forged `[GNUPG:] VALIDSIG` line (gpg percent- and backslash-escapes the raw newline on both channels, so the anchored grep cannot be bypassed); 20-way parallel rate-limiter stress test (exactly bucket-size successes, no budget multiplication; orphan recovery correct across 15/15 instrumented runs); environment-hardening smoke test under `env -i` with LD_PRELOAD/LD_AUDIT/BASH_ENV/SHELLOPTS injected (all neutralised); fresh-clone `git archive` + `make chrome` reproduction of F63L; byte-parity diff of src/dist vs chrome/ and firefox/; verification of the shipped `parcel-host.asc` against a constitution-listed key in a throwaway keyring; embedded `SIGNED_HOST_SHA256` in the generated setup script equals `sha256sum src/parcel-host`.
- **Limitations:** shellcheck not run (unavailable). No Flatpak environment available, so the flatpak wrapper install path was reviewed statically only. The 2562-line setup script was primarily subagent-reviewed with main-session spot checks of its security-critical sections (temp files, parcelrc writes, HOST_HASH application, hash embedding, strict-mode tool vetting). GPG/Chrome-API behaviour outside the mocked surfaces was reasoned about rather than exercised in a real browser.
- **Phase 2:** completed against glm-5.3's exchange table; see Cross-Model Verification. A PoC for the exchanged newline-phantom finding was built and run against the real host in /tmp (results in F60L).

## Findings

Consolidated findings table (this is the table exchanged in phase 2):

| ID | Severity | Confidence | Area | Threat model | Title | file:line |
|----|----------|------------|------|--------------|-------|-----------|
| F63L | L | High | Build / documentation | TM0 | Source builds fail without the maintainer's secret signing key; no documented safe path | src/Makefile:51, README.md:130-145 |
| F64L | L | High | Dev/test tooling | TM5 | Dev/test Dockerfile builds on unpinned, unverified third-party code | Dockerfile:10, Dockerfile:47 |
| F60L | L | High | src/parcel-host | TM4 | Newline-embedded store filenames inject phantom CWD-relative entries into ALLOWED_FILES; decrypting one that exists wedges the host in a `path_uses_links` infinite loop | src/parcel-host:532-560, 709-719 |
| F61L | L | High | parcel-host | TM5, TM0 | Strict-mode detection omits `[ ! -w "$0" ]`: a root-owned but user-writable bootstrap in a non-writable directory enables strict mode while remaining user-editable | parcel-host:63-67 |
| F62L | L | High | agent.js | TM0, TM2 | http-auth token's `intent: "http-auth"` restriction lapses once the challenge resolves; the still-authorised port can then decrypt with any intent, contradicting SECURITY.md's absolute phrasing | src/js/agent.js:861-864, SECURITY.md:158 |
| F65L | L | High | test/popup.test.js | TM5 | No popup-side regression test asserts the F36L `origin: frameOrigin` carriage; a silent drop would re-open cross-origin fill with zero test failures | src/js/popup.js:1577-1584, test/popup.test.js:592-608 |
| F59M | L | Medium | agent.js / WebAuthn | TM0, TM2 | `passkey` runtime port requires no authorisation and no consent; any extension context can enumerate passkey entries and obtain assertion signatures, contradicting SECURITY.md's absolute "no API for signing without the popup" (glm-5.3 rates M; see Cross-Model Verification) | src/js/agent.js:768-773, 779-806, 976-1002; SECURITY.md:134 |
| F66I | I | High | test/ | TM5 | Fixed gates lacking regression tests: F48I CSS.escape and F57L prototype-key gate (the F10L audit-cap and per-container halves duplicate F50I's noted residuals) | src/js/popup.js:1427, src/js/schema.js:115 |
| F67I | I | High | SECURITY.md | TM0 | Stale "No clipboard auto-clear" tradeoff row ("Parcel does not implement this feature") contradicts the v1.0.7 host-side auto-clear documented in the Clipboard copy protection section | SECURITY.md:169 vs SECURITY.md:113-118 |

### F63L - Source builds fail without the maintainer's secret signing key; no documented safe path (LOW)

**Description:** `src/Makefile:51` builds `dist/parcel-host.asc` via `gpg --yes --sign --detach-sign ... --default-key 88FF14D6294AF4036B7F00FF676A3C09E2E47A72`. `src/dist/` is not tracked in git, so a fresh clone has no prebuilt signature and any `make all` / `make chrome` / `make firefox` invocation reaches this rule and aborts with a GPG "no secret key" error for anyone who is not the maintainer. README.md's "Installation from source / Build the extension" section (lines 130-145) documents `make all`, `make chrome`, and `make firefox` with no mention of the signing requirement, and no guidance toward the safe path (generate your own key, self-sign `src/parcel-host`, and add that fingerprint to `VALID_SIGNERS` in parcelrc).

**Threat model(s):** TM0 (documentation tension). The intended security posture - "every executed host script is signed by a key the user has explicitly trusted" - is undermined at the exact moment a source-building user is most likely to weaken it: faced with an opaque build failure, the obvious workarounds (delete the asc rule, bypass signature verification) silently discard the signature chain the bootstrap depends on.

**Evidence:** `src/Makefile:50-53` (hard-coded `--default-key`); `git ls-files src/dist` empty (untracked, so the rule always fires on a fresh clone); README.md:130-145 (no signing mention). Reproduced live: `git archive HEAD` to a scratch dir, `make chrome` fails at the asc step.

**Exploit scenario:** No direct exploit; the finding is the absent documentation/control. A user building from source cannot produce a working, verifiably-signed installation without out-of-band knowledge, and the failure message gives no safe direction. Fail-safe today (the build aborts rather than producing an unsigned bundle), hence LOW.

**Recommended fix:** Parameterise the signing key (e.g. `SIGNING_KEY ?= 88FF14D6...`) and document the self-signing + `VALID_SIGNERS` workflow in README's source-install section, or explicitly document that the asc step requires a maintainer key and how to bypass it safely.

### F64L - Dev/test Dockerfile builds on unpinned, unverified third-party code (LOW)

**Description:** `Dockerfile:10` uses `FROM ubuntu:latest` (a floating tag), and `Dockerfile:47` runs `curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -` - an unpinned remote script executed as root at image build time, with no checksum or signature verification.

**Threat model(s):** TM5 (supply chain). This is the same class as the fixed F37L (unpinned gitleaks download): a compromised NodeSource endpoint or poisoned `ubuntu:latest` tag yields code execution at image build time on maintainer/CI-adjacent machines.

**Evidence:** `Dockerfile:10`, `Dockerfile:47`. Contrast with `scripts/pre-commit-gitleaks:56-64`, which pins v8.30.1 plus per-platform SHA-256 checksums after F37L.

**Exploit scenario:** Absent-control reachability: pinning the base image by digest and verifying the NodeSource script against a pinned hash would block a concrete supply-chain path. Mitigations that keep this LOW: the image is a dev/test convenience only, never shipped; the repo is bind-mounted rather than baked in; and CI (`.github/workflows/ci-unit-tests.yml`) uses `actions/setup-node` instead of this path.

**Recommended fix:** Pin the base image by digest; install Node from Ubuntu's own repositories, or verify the NodeSource setup script against a pinned SHA-256 before execution.

### F60L - Newline-embedded store filenames inject phantom CWD-relative entries; decrypting one that exists wedges the host (LOW)

**Description:** `action_list` splits `find` output on newlines (src/parcel-host:532-560). A store filename containing a newline byte (e.g. `innocent2\ncwd-file.gpg`, or a directory component with a newline producing a slashed phantom like `sub/deep.gpg`) yields a phantom entry whose path is the text after the newline - always a *relative* path, since a filename component can never contain `/`. The phantom passes rule matching (its derived name is rule-checked like any other) and lands in `ALLOWED_FILES` and the popup-visible list. At decrypt time the phantom passes the exact-string whitelist check; if a file with that relative name exists in the host process's CWD, `[ -f ]` passes and `validate_decrypt_path_policy` calls `path_uses_links` (src/parcel-host:709-719), whose upward walk `dirname` bottoms out at `.` - which never equals `$PASSWORD_STORE_DIR` or `/` - looping forever. The host wedges permanently (100% CPU, fork-spamming `dirname`), never answers again, and the extension's ping watchdog eventually reconnects to a fresh host. The hang precedes any GPG invocation, so no plaintext crosses the boundary.

**Threat model(s):** TM4 (hostile store contents). Triggering the hang additionally requires the phantom name to match an existing CWD-relative file and someone (a user clicking the odd entry, or a TM2-compromised extension) to request its decryption.

**Evidence:** src/parcel-host:532-560 (line-split list parsing), src/parcel-host:709-719 (`path_uses_links` loop), src/parcel-host:743-783 (decrypt gate order: whitelist, then `-f`, then path policy, then gpg). Empirically reproduced against the real host with a mock GPG (PoC in /tmp during the review): the phantom `cwd-file.gpg` appeared in the `list` response, and a `decrypt` request for an existing CWD-relative phantom produced no response within 8s and wedged all subsequent messages including `ping`.

**Exploit scenario:** A crafted or attacker-influenced password store (synced, cloned, or shared) contains newline-filenames spraying plausible CWD-relative names. When the victim (or a compromised extension) requests decryption of a phantom whose file exists, the host process wedges until killed - a persistent availability kill of the extension's host channel. No disclosure.

**Recommended fix:** Reject entry paths that are not absolute and store-rooted at list time (e.g. filter `find` output to lines matching `$ROOT/` exactly, or use `find -print0`/`read -d ''` throughout so newline bytes never split entries); additionally bound `path_uses_links` with an iteration cap or an explicit `.`/`/`-normalised termination check.

### F61L - Strict-mode detection omits `[ ! -w "$0" ]` (LOW)

**Description:** `parcel_strict_mode_enabled` (parcel-host:63-67) enables strict mode when the bootstrap is not user-owned and its directory is not user-writable - but never tests whether the bootstrap *file itself* is user-writable. A root-owned bootstrap installed mode 0666 (or otherwise user-writable) into a root-owned non-writable directory enables strict mode while remaining editable by user-level malware. The setup script installs `install -m 0755` (src/parcel-setup.sh:1513), so only a hand-installed or mode-corrupted bootstrap hits this.

**Threat model(s):** TM5/TM0. The documented promise is that strict mode means "the bootstrap is beyond the user's reach" (comment at parcel-host:62; SECURITY.md's system-wide-install language). With a user-writable file, that promise is false: the strict-mode binary vetting is enforced by a script the attacker can rewrite.

**Evidence:** parcel-host:63-67 (no `-w` test on `$0`); src/parcel-setup.sh:1513 (correct 0755 install mode, which is why this is LOW).

**Exploit scenario:** A broken manual install leaves the bootstrap root-owned but user-writable in a root-owned directory. The user believes the strict-mode guarantees hold; user-level malware edits the bootstrap directly. Note the malware gains nothing it could not already do via the writable file - the finding is the false assurance and the check/posture mismatch, not a new privilege.

**Recommended fix:** Add `[ ! -w "$0" ]` to `parcel_strict_mode_enabled` so strict mode only engages when the file itself is also out of reach (matching the documented precondition).

### F62L - http-auth token's intent restriction lapses after the challenge resolves (LOW)

**Description:** The http-auth per-challenge token is documented as "Decryption is restricted to `intent: "http-auth"`; form fills are not permitted from this token" (SECURITY.md:158). The enforcement at src/js/agent.js:861-864 reads `if (this.#pendingAuthCallbacks.has(token) && message.intent !== "http-auth")` - the restriction only fires while the challenge is still pending. The authenticating port's `authorised` flag (set at agent.js:792-794) survives resolution, and the token is deleted from `#pendingAuthCallbacks` when the callback resolves (agent.js:1177-1183). A still-connected port authenticated with that token can thereafter send `decrypt` with `intent: "fill"` or `"detail"` unrestricted.

**Threat model(s):** TM0 primarily; TM2 nominally. The token is observable by the tab's content script (`trigger-http-auth` carries it) and by the popup. Under TM2 this adds nothing beyond the maintainer-accepted F40M posture (any context can already authenticate a popup port with the literal `"broadcast"` token), so there is no incremental exploit - the substance is that a documented absolute restriction silently expires.

**Evidence:** src/js/agent.js:779-806 (auth gate), 861-864 (pending-only intent check), 1177-1183 (resolution deletes the record); SECURITY.md:158 (absolute phrasing).

**Exploit scenario:** A compromised content script observes a 401 challenge token, authenticates a popup-named port with it, waits out the challenge (or lets it time out), then drives `intent: "fill"` decryptions of whitelisted entries - which it could already do via `"broadcast"`, hence LOW.

**Recommended fix:** Either make the restriction absolute for the token's lifetime (track http-auth tokens until port disconnect, not until challenge resolution), or soften SECURITY.md's phrasing to "while the challenge is pending".

### F65L - No popup-side regression test for the F36L origin carriage (LOW)

**Description:** The F34M destination-origin guard (src/js/integration.js:1814-1818) only fires when the fill message carries an `origin` property, and F36L's fix made the primary popup path send `origin: frameOrigin` (src/js/popup.js:1577-1584). The popup fill-flow test (test/popup.test.js:592-608) asserts `action`, `token`, and `plaintext` but never `origin`. A future refactor that drops the `origin` field would silently disarm the guard on the primary fill path - re-opening the F34M cross-origin fill class - with zero test failures. This is the same finding class as F56L (rated LOW): a defence-regression detector gap over a security gate.

**Threat model(s):** TM5 (regression of a shipped protection via unnoticed repo change).

**Evidence:** test/popup.test.js:592-608 (assertions listed); src/js/popup.js:1583 (the field under test); src/js/integration.js:1814 (`hasOwnProperty`-gated check).

**Exploit scenario:** No direct exploit; absent test control whose presence would catch re-opening of the F34M path.

**Recommended fix:** Assert `msg.origin` equals the frame origin in the popup fill-flow test.

### F59M - `passkey` port requires no authorisation and no consent (LOW; severity disputed - glm-5.3 rates M)

**Description:** Any extension context can open a port named `passkey`; the per-port-type allow-list (src/js/agent.js:768-773) grants it the `passkey` action, and the authorisation gate at agent.js:779-806 applies only to `popup`-named ports. The `candidates` phase enumerates passkey entries for an rpId, and the `assert` phase drives host-side assertion signing over a caller-supplied `clientDataJSON` - all without the consent popup. SECURITY.md:134 states "there is no API for signing without the popup". The host still enforces whitelist membership, passkey class, rpId binding against entry contents, `allowCredentials`, and the rate limiter; private key material never leaves the host.

**Threat model(s):** TM2 (a compromised content script can do all of this; a hostile *page* cannot - pages cannot open extension ports, and the bridge re-derives everything isolated-side, so the documented consent gate holds against TM1). TM0 for the documentation tension.

**Evidence:** src/js/agent.js:768-773 (allow-list), 779-806 (popup-only auth gate), 937-975 (candidates), 976-1002 (assert); src/parcel-host:851-963 (host-side enforcement set); SECURITY.md:134 (absolute phrasing).

**Exploit scenario:** A compromised content script connects a `passkey` port, enumerates the victim's passkey entries for a target rpId, and obtains assertion signatures over attacker-built `clientDataJSON` (e.g. binding a real login challenge from that RP) - silent passkey authentication, bounded by the rate limiter (burst 10, then ~10/hour) and recorded by the audit log when enabled.

**Why LOW here (disagreement with glm-5.3's M):** under this review's TM2 defence-in-depth scope, a gap exploitable only from an already-compromised extension context is not a finding unless it defeats a control specifically documented as a TM2 mitigation. The documented TM2 boundary is the host (whitelist, rate limiter, audit, no key material) - all of which hold here. The consent gate is documented as a page-facing protection ("A page cannot silently authenticate you"), and the compromised-extension "cannot" list makes no consent promise; the maintainer's F40M response additionally establishes that content-script compromise is treated as extension compromise and that extension-side tokens are not TM2 defences. The residual substance is the absolute sentence "there is no API for signing without the popup", which is true only against pages - a TM0 documentation tension. Confidence: Medium (the facts are certain; the severity hinges on how the documentation is read).

**Recommended fix:** Either document that consent is a page-facing control only, or close the port: require the ceremony to be initiated through the consent flow (e.g. bind `assert` to a popup-issued token as the fill path does), noting the F40M precedent that such a gate is not considered a TM2 defence.

### F66I - Fixed gates lacking regression tests: F48I CSS.escape and F57L prototype-key gate (INFORMATIONAL)

**Description:** No test asserts the F48I `CSS.escape(entry.path)` call (src/js/popup.js:1427) or the F57L `hasOwnProperty` unknown-key gate (src/js/schema.js:115); reverting either fails zero tests. The audit-field-truncation and per-container-isolation halves of the same observation duplicate F50I's already-noted residuals and are not re-reported. Defence-regression detectors only; no live hole.

**Recommended fix:** Add a popup render test with a selector-hostile entry path, and a schema test rejecting `__proto__`/`constructor` keys.

### F67I - Stale "No clipboard auto-clear" tradeoff row (INFORMATIONAL)

**Description:** SECURITY.md:169's tradeoff row states "Parcel does not implement this feature" for clipboard auto-clear, but v1.0.7's host-side clipboard action implements exactly that (documented at SECURITY.md:113-118, including `clipboardTimeout` at :206). The row's underlying rationale (avoiding a `clipboardRead` permission) still holds for the browser-API fallback path, but the absolute claim is stale and contradicts the same document.

**Recommended fix:** Reword the row to scope the tradeoff to the browser-clipboard fallback path.

## Regression Checks

One line per prior fixed finding, verified against the current tree (main session, cross-checked by subagents):

- **F52C** (#144, anchored VALIDSIG): `grep '^\[GNUPG:\] VALIDSIG '` present at parcel-host:628; live-verified non-bypassable with GnuPG 2.4.9 and a raw-newline-UID key. PASS.
- **F53M** (#175, atomic rate state): rename-based single-winner lock with noclobber create, 5s orphan recovery, 10s fail-closed budget (src/parcel-host:150-215); 20-way stress test could not multiply the budget. PASS.
- **F54L** (#170, TOTP validation): digits coerced and restricted to 6-10, period to 1-3600 (src/js/helpers.js:50-54). PASS.
- **F55L** (#171, crossOrigin): real `crossOrigin` emitted, `topOrigin` included when cross-origin and determinable (src/js/webauthn.js:233-241). PASS.
- **F56L** (#172, adversarial VALIDSIG test): test/native-host.test.js:593 crafts a malicious-UID line passing the old unanchored grep and failing the anchored one. PASS.
- **F57L** (#174, schema prototype gate): unknown-key gate uses `Object.prototype.hasOwnProperty` (src/js/schema.js:115); `__proto__`/`constructor` keys rejected. PASS.
- **F58L** (#174, MetaSchema recursion): object-level `items` recursion with cyclic re-entry guard (src/js/schema.js:47, 119-124); nested typos rejected. PASS.
- **F42L** (#130, passkeyDir validation): `..`, leading `/`, control chars, glob metachars rejected host-side (src/parcel-host:1007) and schema-side (src/js/schema.js passkeyDir pattern). PASS.
- **F45L** (#131, rsync --delete): present in both chrome and firefox targets (Makefile:43,50). PASS.
- **F48I** (#132, CSS.escape): `CSS.escape(entry.path)` at src/js/popup.js:1427. PASS.
- **F35M** (#116, persisted bucket): state file persistence across restarts (src/parcel-host:88-135; test/native-host.test.js:2846). PASS.
- **F36L** (#118, primary fill origin): popup fill sends `origin: frameOrigin` (src/js/popup.js:1583); content script enforces at src/js/integration.js:1814-1818. PASS.
- **F37L** (#123, gitleaks pinned): scripts/pre-commit-gitleaks pins v8.30.1 with per-platform SHA-256 verification. PASS.
- **F38I** (27dd6f2, port comment): PORT_ACTIONS comment matches the allow-list (src/js/agent.js:764-773). PASS.
- **F34M** (#106, broadcast origin validation): broadcast fill carries `origin` (src/js/agent.js:925-931) and the destination frame enforces it (src/js/integration.js:1814). PASS.
- **F18M** (#68, CSP directives): `connect-src 'none'; frame-src 'none'; base-uri 'self'` present (src/manifest.json:30) and in both built manifests. PASS.
- **F19M** (#67, lifecycle): onStartup/onInstalled plus idempotent `#ensureNativeConnected` (src/js/agent.js:88-93, 148-151). PASS.
- **F20M** (#69, port action allow-list): PORT_ACTIONS map with decrypt/match restricted to authorised popup ports, integration ports config-only, unknown actions rejected (src/js/agent.js:768-816). PASS.
- **F22L** (#71, HOST_HASH basis): hash computed over exact script bytes via `jq -rj '.script'` (parcel-host:641). PASS.
- **F29L** (#71, quoted $SHA256): `"$SHA256"` quoted in command position (parcel-host:641). PASS.
- **F30L** (0c9be39, no GPG status leak): signature failure sends a static message; `$OUT` only logged (parcel-host:596-601, 630-634). PASS.
- **F31L** (ffeae49, action regex gate): `^[a-zA-Z0-9_]+$` gate before `type -t` dispatch (parcel-host:665-671). PASS.
- **F17L** (#57, link policy before traversal): `collect_roots` refuses a symlinked store root when allowLinks is false and only collects policy-compliant roots before any `find` (src/parcel-host:303-310). PASS.
- **F14L/F10L** (#56, audit field caps): control-char stripping plus 128/1024/1024/4096 caps (src/parcel-host:636-646, 805-815). PASS.
- **F11L** (#55, CSP declared): explicit `extension_pages` CSP present. PASS.
- **F1M** (#46, temp keyring): mktemp keyring, `--no-default-keyring --keyring`, `GNUPGHOME=/dev/null`, removed on both paths (parcel-host:581-603). PASS.
- **F2M** (#48, control-char stripping): all audit fields stripped. PASS.
- **F9L** (#49, sha256 after parcelrc): SHA256 resolution occurs after `load_parcelrc` (parcel-host:497). PASS.
- **F25T** (0600 logfile): `chmod 0600 "$LOGFILE"` on creation (parcel-host:471). PASS.
- **F41L** (#129, multi-sig): first-trusted-non-revoked VALIDSIG loop (parcel-host:612-635); covered by tests. PASS.
- **F47L** (changes_since return): `return 0` after invalid `.since` (src/parcel-host:493-496). PASS.
- **F50I** (#132, port-action coverage): non-whitelisted port-action tests present (test/agent.test.js:601,613); the audit-truncation and per-container-isolation halves remain unasserted (see Residual Observations). PARTIAL (as previously noted by maintainers).

No fix was found reverted, partially reverted, or undermined by later changes.

## Deliberate Tradeoffs

Each documented/accepted tradeoff was re-derived from findings.md and SECURITY.md and tested against the current code:

- **F40M (broadcast/self-issued auth token):** the implementation matches the documented correlation-identifier intent (src/js/agent.js:694-699 comment); the port allow-list still bounds which actions any port can reach. Acceptance rationale holds.
- **F43L (Firefox ancestorOrigins fallback to `"*"`):** code matches the documented behaviour (src/js/integration.js:253-260); impact remains popup-position confusion only. Holds.
- **F44L (forgeable conflict event):** the conflict notice path still re-derives everything isolated-side; dismissal only suppresses future notices. Holds.
- **F46L (state-file fail-open / symlink-follow, same-UID actor):** `load_state` still fails open on unloadable state and `save_state` still writes through a symlinked state file; the actor remains a same-UID process outside Parcel's containment. Holds (see Residual Observations for the related lock-stall note).
- **F33T (config endpoint exposes passdir):** unchanged; accepted. Holds.
- **F21T (backup keys in default VALID_SIGNERS):** unchanged; the default list still contains all four release keys (parcel-host:473). Holds.
- **F23T (default burst size):** defaults remain decryptBucket 10 / decryptRate 0.00277; the popup now additionally warns on disabled/excessive rate limiting (#177), strengthening the rationale. Holds.
- **F24T (LOGFILE unvalidated):** parcelrc remains a trusted file, now further hardened by the whitelist parser and 0600 enforcement. Holds.
- **F15T (audit line assembly unbounded):** per-field caps remain the only bound; accepted. Holds.
- **F16T (config-dir permissions):** unchanged; accepted. Holds.
- **F12T (search ReDoS), F13T (shadow.js MAIN-world patch), F8T (history hashing), F6T (cross-origin fill warning-only), F7T/F26T (WAR breadth), F39T (page-stylable popup), F4T (default-allow-all), F3T (no-network is governance), F5T (parcelrc as code), F32T (non-constant-time hash compare), F49I/F51I (token growth; fill-value origin edge):** all re-examined; implementations match their documented rationales. The WAR list was additionally re-verified entry-by-entry against actual code load sites (each remaining entry is dynamically imported from a page-context script or is the popup iframe document). Holds.
- **Signer-revocation best-effort caveat (SECURITY.md):** the state-file blacklist is a replaceable cache as documented; `repair_state` ensures an unusable file is repaired so a later bootstrap enforces the shipped list (src/parcel-host:225-257). Implementation matches documentation. Holds.

No tradeoff was found to diverge from its documentation.

## Residual Observations

No reachable exploit path was identified for any of the following; they are recorded for completeness and future hardening:

1. **Newline-in-filename `find:` error-line injection (TM4):** a store file whose name contains a newline and a `find:` prefix injects a fake error line into `action_list`'s stderr separation, failing the scan closed; it also desyncs the readlink line-count check (src/parcel-host:545-560). The broader phantom-entry consequences of the same newline splitting are finding F60L; this residual covers only the error-injection nuance. Fail-closed; a store writer has strictly easier availability attacks.
2. **Rate-limit lock live-stall double-spend (TM4, same-UID):** a lock holder stalled longer than the 5s orphan-recovery age (SIGSTOP, extreme load) can have its lock recovered by another host, and both spend from the same loaded state; the multiplier is bounded by concurrent hosts. Requires same-UID action, squarely within F46L's accepted scope. The critical section never waits on the extension, so TM2 cannot reach it.
3. **`save_state` follows a symlinked state file (TM4, same-UID):** `lock_state` renames a symlinked `$STATEFILE` to `.locked` and the `printf >` write follows it (src/parcel-host:132), inconsistent with `repair_state`'s explicit `! -L` guard (src/parcel-host:229). Same-UID only; `load_state` itself refuses symlinks. Within F46L's accepted scope.
4. **32-bit length-prefix edge (TM2, self-DoS):** on a 32-bit `long`, `printf %ld "0xFFFFFFFF"` yields -1, bypassing the 16MiB check into `head -c -1` (parcel-host:651-657). Verified impossible on 64-bit; extension-self-DoS only.
5. **Unanchored user rule regexes (TM0):** jq `test()` is a partial match, so `"websites/.*"` also matches `evil/websites/x`. Documented "regex matched against the entry name" semantics; the default injected rules are anchored. Users writing rules should anchor them; a README note could help.
6. **Symlinked `.gpg-id` followed in the passkey-create walk (TM4):** the `-f` test and read follow symlinks, so recipients could come from an out-of-store file (src/parcel-host:1057-1076). Identical to `pass`'s own store-trust model; a store writer can plant recipients directly.
7. **`passkey_op_create` consumes no rate-limit token (TM2):** no decryption occurs, so a compromised extension can CPU-spam key generation and obtain unlimited armored blobs - encrypted to the store's own recipients, hence unreadable by it. Within the documented TM2 envelope.
8. **Strict-mode checks do not walk grandparent directories (TM4):** binary/PATH checks test the file and its immediate directory, not grandparents (e.g. a user-writable `/usr` would allow renaming `/usr/bin`). Requires an already-broken system.
9. **Far-future `DECRYPT_BUCKET_LAST` (TM4, same-UID):** refill goes negative and denies until wall-clock catches up; fail-closed; same-UID tamper within F46L's scope.
10. **`entry.rule.tag` without optional chaining (src/js/popup.js:1444):** reachable only if jq/Oniguruma and JS RegExp diverge on the same pattern+name (ConfigSchema already rejects patterns JS cannot compile); impact is a render exception caught by `scheduleRender`, not disclosure. Consistency fix suggested (`entry.rule?.tag`).
11. **History recorded on fill ack, pre-validation (src/js/popup.js:1585-1597):** the ack precedes the destination-origin check, so a refused fill still writes history metadata. Convenience metadata only (F8T); cosmetic.
12. **`base32ToArrayBuffer` silently decodes invalid base32 characters** (src/js/helpers.js:15-33): `indexOf` -1 becomes `& 0x1f`; a malformed store secret yields a wrong token, not a security event.
13. **User-gestured docs link (src/js/popup.js:1395-1400):** the passkey-conflict "Learn more" button opens the project's GitHub README via `window.open(..., "noopener,noreferrer")`. User-initiated navigation akin to `homepage_url`, in mild tension with a literal reading of "no network access, for any reason"; not telemetry. Informational only.
14. **Unasserted test halves of F50I:** audit-field truncation and per-container history isolation lack explicit tests; the F1M anti-pollution flags (`--no-default-keyring`/`--keyring`) are unasserted because the mock gpg intercepts first. Defence-regression detectors, not live holes; consistent with the maintainer's "Noted" response.
15. **Flatpak manifest path discrepancy (functional, uncertain):** `install_flatpak_wrappers` (src/parcel-setup.sh:1690-1698) writes flatpak manifests to the browser's standard user-level manifest dir, while README's manual flatpak instructions use the `~/.var/app/$APP_ID/...` path. Unverifiable without a flatpak environment; no security impact either way (the wrapper execs the same verified host).
16. **shellcheck coverage:** `make test` shellchecks only the two hosts and the setup script; `scripts/*.sh` and `example/*.sh` get `bash -n` only.

## Things Done Well

- **The F52C fix is robustly verified, not merely present:** anchored grep, FPR_RE validation of both extracted fingerprints, blacklist matching on primary and subkey, fail-closed static errors - and a live GnuPG 2.4.9 test confirms a forged status line cannot be smuggled through a malicious UID on either output channel.
- **The rate-limiter lock is genuinely sound:** single-winner rename invariant, noclobber fresh-create, mtime-fresh-at-claim, fail-closed exhaustion, `trap unlock_state EXIT` on every path, and state content whitelist-validated before `eval`. A 20-way stress test could not multiply the budget.
- **Passkey defence-in-depth is exemplary:** rule-based classification plus a content-marker backstop with forward-version refusal, rpId binding and allowCredentials enforced immediately before signing, and private key material confined to pipes - it never enters a bash variable that could leak, let alone the browser.
- **The parcelrc whitelist parser is a significant hardening over sourcing:** canonical `KEY="value"` lines only, `$HOME`-only expansion tokens, per-key validation, fatal refusal on invalid VALID_SIGNERS/HOST_HASH. Combined with the environment whitelist and privileged re-exec, the bootstrap's TM3/TM4 posture measurably works (verified live).
- **Audit-log hygiene is by construction:** every log-write site is plaintext-free; plaintext never appears in a command argument anywhere, so even the `exec 2>&5` stderr capture cannot leak it.
- **Source-distribution parity is real and verified:** bundles byte-identical to src/, the Firefox rewrite is minimal, no transpilation anywhere, and the Chrome webstore key injection derives exactly the extension ID referenced by the native manifests.
- **The test suite is adversarial where it matters:** VALIDSIG injection, concurrent-bucket lost-update, lock-exhaustion fail-closed, symlink revalidation at decrypt time, port-action rejection, origin-mismatch fill refusal - and the fetch mock turns any latent network call into a loud test failure.

## Cross-Model Verification

Phase 2 completed against glm-5.3's exchange file (`security-review-table-glm-5.3-20260912-099857c.md`, 1 M / 4 L / 2 I). Only the exchange table was read; the other model's full report was never accessed. Every table entry was independently reproduced against the code before adoption:

- **F59M (passkey port, rated M):** behaviour confirmed (no authorisation or consent gate on the `passkey` port; verified at src/js/agent.js:768-773, 779-806, 976-1002). **Severity disagreement:** this review rates it LOW (F59M). glm-5.3 rated M; this review's reasoning: the gap is reachable only from an already-compromised extension context (pages cannot open extension ports, so the documented consent gate holds against TM1), the documented TM2 boundary (host whitelist, rpId binding, rate limiter, audit, no key material) is not defeated, and the maintainer's F40M response establishes that extension-side tokens are not TM2 defences. The residual substance is TM0 documentation tension in the absolute sentence "there is no API for signing without the popup". The verdict was not changed to achieve consensus.
- **F60L (newline phantom entries, L):** confirmed and adopted as F60L with independent PoC against the real host (phantom appeared in the `list` output; decrypting an existing CWD-relative phantom wedged the host - no response to the decrypt or a subsequent ping). This review additionally established that absolute-path phantoms are impossible (filename components cannot contain `/`), capping impact at host DoS with no plaintext leak.
- **F61L (strict-mode `-w` omission, L):** confirmed (parcel-host:63-67 lacks the test; setup script installs 0755, so a broken/manual install is required). Adopted as F61L.
- **F62L (http-auth intent restriction lapses, L):** confirmed (agent.js:861-864 checks only while pending; the port stays authorised after resolution). Adopted as F62L; this review emphasises the TM0 documentation divergence over the TM2 angle, since the F40M posture already grants equivalent capability via the `"broadcast"` token.
- **F65L (no popup-side origin-carriage test, L):** confirmed (test/popup.test.js:592-608 asserts action/token/plaintext, never origin). Adopted as F65L.
- **F66I (four missing regression tests, I):** partially confirmed. The F48I and F57L test gaps are new and adopted as F66I; the audit-cap-truncation and per-container-isolation halves duplicate F50I's already-noted residuals and were not re-reported.
- **F67I (stale clipboard tradeoff row, I):** confirmed (SECURITY.md:169 vs :113-118). Adopted as F67I.

No non-reproductions. One severity disagreement (F59M). Both exchange files were deleted after finalisation per protocol.

## Second-Look Review

Honest answers to the required checklist:

- **Reachability:** the two phase-1 findings survived the reachability requirement in their absent-control/documentation-tension form, and both were reproduced or pattern-verified live (fresh-clone build failure; Dockerfile lines read directly). Of the seven exchanged findings, six were confirmed and adopted (one with a partial dedup against F50I), each with an independent verification trail - including a live PoC for F60L - and one was confirmed in behaviour but disputed in severity (F59M). No "looks suspicious" finding was allowed through; nine candidate issues from the subagents were demoted to Residual Observations precisely because no reachable path exists under the stated threat models.
- **Superficial areas:** (1) `test/setup/*.test.js` was run (40/40 pass) but not read line-by-line by the main session; (2) the setup script's 2562 lines were primarily subagent-reviewed with main-session spot checks of security-critical sections; (3) popup.js rendering branches beyond the security sinks were skimmed by the main session (the extension subagent read them in full); (4) no real-browser or flatpak dynamic testing was possible in this container.
- **Unverified assumptions:** the chrome-api-mock's fidelity to real Chrome port semantics (relies on the build subagent's analysis plus the suite passing); GPG status-output format on versions other than 2.4.9 (the anchored-grep fix was live-verified on 2.4.9 only); the flatpak wrapper install path (static review only).
- **Tradeoff misattribution:** every accepted item in findings.md was re-derived and tested against current code before exclusion; F46L's rationale (same-UID actor out of scope) was applied to demote residuals 2, 3, and 9, and F48I's class to demote residual 1.
- **jq call sites / quoting / dispatch:** all `jq` extractions in both hosts use `--arg`/`--rawfile` or regex-gated fields; every command-position variable in the bootstrap was mechanically grepped and manually traced; the action dispatch is regex-gated and exactly eight intended `action_*` functions exist.
- **Origin validation on every fill/decrypt path:** proven for the primary popup path (popup sends `frameOrigin`; content script enforces), the broadcast best-target path (agent stamps `origin`; content script enforces), and mid-decrypt navigation (the reconnecting tab port lands on the new document's content script, whose origin differs and refuses). `fill-value` carries no origin - the maintainer-rejected half of F36L (F51I), not re-reported.
- **Severity consistency:** all seven LOW findings are defensible as such: F63L fails safe today; F64L is dev/test-only with CI not using the path; F60L is a multi-precondition DoS with no disclosure; F61L requires a broken install and grants no new privilege; F62L adds nothing beyond the accepted F40M posture; F65L is a test-gap detector; F59M's facts are certain but its severity hinges on documentation reading (Medium confidence, dispute recorded). Only the six permitted letters are used (L/I here; T referenced only for prior findings).
- **Prior-review access:** none (filenames-only directory listing per §0, recorded in Methodology).
- **Confidence calibration:** F63L - High (live reproduction); would change: a documented self-signing workflow discovered elsewhere in the repo. F64L - High (lines read directly); would change: evidence the Dockerfile builds shipped artifacts. F60L - High (live PoC); would change: a demonstration that `path_uses_links` terminates for relative paths (it does not). F61L - High (code read); would change: an install path that creates user-writable bootstraps by default. F62L - High (code read); would change: evidence the port is de-authorised on resolution. F65L - High (test read); would change: an origin assertion found in the popup tests. F59M - Medium (facts certain, severity disputed); would change: a maintainer statement that consent is intended as a TM2 control. F66I/2I - High (directly read).

## About This Review

- **Model:** kimi-k3 (kimi-k3-flex), via GitHub Copilot CLI.
- **Date:** 2026-09-12.
- **Commit:** `099857c` (tag `v1.0.7`; release review - HEAD is at the tag, working tree clean).
- The committed `security-review/prompt.md` is the canonical record of what was prompted.
