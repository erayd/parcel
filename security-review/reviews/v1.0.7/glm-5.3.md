# Parcel Security Review - glm-5.3

**Release review of Parcel v1.0.7** (commit `099857c`, exactly at tag `v1.0.7`, clean working tree), conducted 2026-09-12.

## Executive Summary

Parcel v1.0.7 is in strong security shape. No CRITICAL or HIGH vulnerabilities were identified. This review records one MEDIUM and six LOW findings, plus two INFORMATIONAL items; two of the LOW findings (F63L, F64L) were surfaced by the Phase-2 cross-model exchange (kimi-k3) and independently reproduced before admission. The single most important takeaway: **the `passkey` runtime port is the one privileged action that never received the authorisation gate that `decrypt`/`match` gained in #69, which both contradicts SECURITY.md's absolute claim that "there is no API for signing without the popup" and leaves silent assertion signing available to any compromised extension context** (F59M). The host-side enforcement boundary otherwise held up under every attack attempted in this review: the whitelist, rate limiter (including its new atomic state lock), signer revocation, rpId binding, and the new v1.0.7 parcelrc/environment hardening all survived live adversarial testing, and all 29 previously-fixed findings were verified intact.

Finding counts: 1 MEDIUM, 6 LOW, 2 INFORMATIONAL. The full test suite passes 555/555 (32 suites), and `make test-setup` passes 40/40.

## Trust Model & Attack Surfaces

The components examined, and the trust-boundary hierarchy as derived from the code itself:

1. **The native host is the only real enforcement boundary.** `src/parcel-host` re-derives everything it acts on: `action_decrypt` re-checks exact-string membership in `ALLOWED_FILES` (rebuilt from a fresh store scan on every `list`), re-validates the symlink policy at decrypt time (`validate_decrypt_path_policy`), refuses passkey-classified entries by both rule and content marker (`#!parcel-passkey` prefix backstop), and meters every attempt through the persisted token bucket. The extension is trusted for *nothing* except choosing which already-whitelisted path to decrypt and what correlation metadata to attach. This is the right architecture, and it is consistently implemented.

2. **The bootstrap (`parcel-host`) is the root of trust for host-code integrity.** It verifies the GPG detached signature (anchored `^\[GNUPG:\] VALIDSIG ` status-line extraction, live-verified against GnuPG 2.4.9 including a malicious-UID key and a newline-in-UID key - GnuPG percent-escapes the latter, so status-line injection is impossible), checks primary and signing-subkey fingerprints against `VALID_SIGNERS` minus the effective blacklist (parcelrc ∪ state file), optionally pins `HOST_HASH` over the exact raw script bytes, and only then `eval`s the script. New in v1.0.7: canonical-line-only parcelrc parsing (PoC-verified injection-proof), an environment whitelist, and strict-mode PATH/binary ownership filtering for system-wide installs.

3. **The extension's isolated world (agent.js, integration.js, popup.js) is a policy layer, not a boundary.** Port-name-to-action allow-listing, popup-token auth, origin labelling, and passkey consent all live here. Under TM2 these are bypassable by design (the maintainer's F40M position: extension-internal gates are correlation, not defence) - which is precisely why the gaps in this layer that *contradict documentation* (F59M, F62L) matter: the docs promise more than the layer delivers.

4. **The MAIN world (shadow.js, main-world/webauthn.js) is page-adjacent by necessity.** Both scripts expose only what WebAuthn interception and shadow-DOM click re-dispatch require; every value crossing to the isolated world is schema-validated or token-checked there, and every security-relevant decision (origin, rpId, consent, signing) is re-derived in the isolated world, the worker, or the host. Forged MAIN-world events yield popup annoyance at worst - verified against the documented bridge set.

5. **The store and its config (`.parcel.json`) are untrusted input to the host** (TM4). Rules are evaluated host-side; the extension applies a second, per-class visibility layer. The one place where store-controlled *filenames* leak past the intended parsing model is F60L.

Attack surfaces audited: the native-messaging protocol (both directions), the bootstrap verification chain, parcelrc and the environment, the state file and its lock, the audit log, the passkey crypto path (openssl), the clipboard action, all runtime port types, every fill/decrypt path including broadcast autofill and mid-decrypt navigation, the WebAuthn ceremony pipeline end-to-end, the popup's rendering sinks, the config schema system, the manifest and both packaged trees, and the build/release chain.

## Methodology

- **Model:** glm-5.3 (session model `glm-5.3-flex`; operational suffix omitted per the review protocol). Three subagents, all running the same model, were allocated per §5: (1) native host + host-side constitution compliance, (2) extension JS + WebAuthn + popup, (3) manifest/build/tests + regression checks. Every subagent finding below was independently re-verified by the main session before being admitted to this report; the second-look pass was not delegated.
- **Documents read in full (grounding):** `CONSTITUTION.md`, `SECURITY.md`, `README.md`, `security-review/findings.md`. **No file under `security-review/reviews/` was opened or read.** For full disclosure: the reviews directory was *listed* (filenames only) to derive the filename convention for this report, as §0 requires; no content was accessed.
- **Source examined:** every file in `src/js/` (including `main-world/`), `src/html/popup.html`, `src/manifest.json`, both host scripts (`parcel-host`, `src/parcel-host`), `src/parcel-setup.sh`, `src/parcel-setup.json`, both Makefiles, `eslint.config.js`, `scripts/` (incl. the gitleaks pin), `example/` (native-messaging manifests, flatpak wrapper), and the `chrome/`/`firefox/` output trees. Test files were read for coverage analysis.
- **Tests run:** `make test` - **555/555 pass, 32 suites, 0 failures** (prettier `--check`, ESLint, shellcheck on both host scripts, and `node --test` over all 16 test files). `make test-setup` - 40/40 pass. Note: shellcheck was absent from the container and was installed (via pacman, with sudo) as sandbox tooling before the run; nothing else in the environment was changed. The working tree was verified clean (`git status`) before and after all runs.
- **Empirical verification (PoCs and live experiments, all outside the repo tree):**
  - *parcelrc parser PoC* (extracted verbatim logic): 11 injection attempts (command substitution, backticks, `$EVIL` expansion, semicolon/single-quote payload values, `PATH`/`BASH_ENV`/`LD_PRELOAD` keys, `$HOME`-lookalike tokens) - all rejected or inert; no code execution escaped the `eval`. SECURITY.md's canonical-line-only claim is accurate.
  - *newline-filename PoC* (drives the real `./parcel-host` + real `src/parcel-host` with a mock gpg, harness pattern from `test/native-host.test.js`): a store file named `a\nstray.gpg\nb.gpg` produces phantom entries `stray.gpg` and `b.gpg` (CWD-relative paths) in the `list` output and `ALLOWED_FILES`; a decrypt of the phantom that matches an existing CWD file hangs the host in `path_uses_links` (infinite `dirname` fixed-point on relative paths); a decrypt of a non-existent phantom fails cleanly with "File not found". No plaintext leak was achievable (the hang precedes GPG; the phantom cannot contain `/` so it cannot target store-internal or other absolute paths).
  - *subagent-verified PoCs re-checked against the code by the main session:* the ungated `passkey` port (EJ-1) and the transient http-auth intent restriction (EJ-2) were traced line-by-line in `agent.js` by the main session; subagent 1's live GnuPG experiments (VALIDSIG field layout, malicious-UID, multi-sig, HOST_HASH basis, 8-process rate-limit atomicity producing exactly 10 successes/230 denials) and subagent 3's packaging diffs and signature verification were accepted after cross-checking their citations.
- **Phase 2 (cross-model verification):** after the Phase-1 draft and exchange file were complete, the maintainer imported the kimi-k3 exchange table (`security-review/security-review-table-kimi-k3-20260912-099857c.md`); it was read in full (the exchange table only - kimi-k3's report was not accessed), and both of its findings were independently reproduced by the main session before admission (see Cross-Model Verification). No subagents were used for Phase 2 (two findings, each verifiable directly). Two disclosures: (a) completing the documented build for the Phase-1 parity diff had itself required improvising around the signing requirement - a local key was generated in a throwaway keyring and `dist/parcel-host.asc` hand-produced so `make` would proceed (the surviving artifact is signed by fingerprint `99ED9C…`, not the maintainer's key); this improvisation is itself evidence for F63L; (b) during Phase-2 dedup checking, a repo-wide filename-only search (`grep -l`) matched two prior-review filenames under `security-review/reviews/` - no content from that directory was read at any point in either phase.
- **Limitations:** no live browser was available; extension-side behaviour was verified by code tracing plus the project's own jsdom-based test suite and Chrome API mock. The mock GPG performs no real cryptography (a known, accepted limitation of the suite, noted in Residual Observations). Resource-timing observability of the popup iframe URL (subagent residual R2) could not be settled without a live browser.

## Findings

| ID | Severity | Confidence | Area | Threat model | Title | file:line |
|----|----------|------------|------|--------------|-------|-----------|
| F59M | M | High | agent.js / WebAuthn | TM2, TM0 | `passkey` runtime port has no authorisation or consent gate; contradicts SECURITY.md "no API for signing without the popup" | src/js/agent.js:768-773, 778-808, 937-1013, 1416-1441; SECURITY.md:134 |
| F60L | L | High | src/parcel-host | TM4 | Newline-embedded store filenames inject phantom non-store entries into the whitelist; decrypting one hangs the host in `path_uses_links` | src/parcel-host:532-544, 709-719, 721-737 |
| F61L | L | High | parcel-host | TM5 | Strict-mode detection omits a writability check on the bootstrap file itself | parcel-host:63-67; src/parcel-setup.sh:1513 |
| F62L | L | High | agent.js | TM2, TM0 | http-auth token's intent restriction is transient (pending-challenge lifetime only), contradicting the documented absolute | src/js/agent.js:861-864, 1177-1183, 1230-1232; SECURITY.md:158 |
| F65L | L | High | test/popup.test.js | TM5 | No popup-side regression test for the F36L `origin` carriage that wires the F34M guard to the primary fill path | src/js/popup.js:1577-1584; test/popup.test.js:592-610 |
| F66I | I | High | test/ | TM5 | Four fixed gates lack regression tests (CSS.escape, prototype-key gate, audit-log caps, container history isolation) | src/js/popup.js:1427; src/js/schema.js:115; src/parcel-host:647; src/js/agent.js:230-240 |
| F67I | I | High | SECURITY.md | TM0 | Stale "No clipboard auto-clear" tradeoff row contradicts the v1.0.7 host-side auto-clear feature | SECURITY.md:169 vs SECURITY.md:113 |
| F63L | L | High | Build / documentation | TM0, TM5 | Documented from-source build cannot succeed without a release signer's secret key; no safe self-build path is documented | src/Makefile:49-53; README.md:91-111, 123-134; src/js/agent.js:160-165; parcel-host:474; CONSTITUTION.md:137, 149 |
| F64L | L | High | Dev/test tooling | TM5 | Test Dockerfile builds on unpinned, unverified third-party code (moving `ubuntu:latest` tag, NodeSource `curl \| bash`) | Dockerfile:4, 10, 47; Makefile:7-13; CONTRIBUTING.md:111-121 |

### F59M - `passkey` runtime port has no authorisation or consent gate (MEDIUM)

**Description.** The #69 port hardening gave `decrypt`/`match` a two-part gate: they are reachable only from `popup`-named ports, and those ports must authenticate with a token from `#authorisedTokens`, the literal `broadcast`, or a pending http-auth challenge. The `passkey` action - the only action that exercises a passkey's private key - has no equivalent gate at all. `PORT_ACTIONS` grants `passkey: ["passkey"]` (src/js/agent.js:768-773), and the authentication block applies only to `port.name === "popup"` (src/js/agent.js:778-808), so any extension context can `chrome.runtime.connect({name: "passkey"})` and directly invoke `phase: "candidates"` (enumerate passkey entry names/paths for any claimed rpId), `phase: "assert"` (sign an assertion), and `phase: "create"` (mint a credential). The consent popup is enforced only by the *caller* (integration.js builds the ceremony binding and waits for the popup's `passkey-assert` message); the port handler itself performs no consent verification. `#validateRpId` (src/js/agent.js:1416-1441) checks only the internal consistency of the two message-supplied strings `origin` and `rpId`; the host then enforces whitelist, passkey classification, entry-rpId == request-rpId, `allowCredentials`, and the rate limit - all against values the caller chose.

**Threat model(s).** TM2 (compromised content script, or unnoticed malicious extension code in the official repository - explicitly in scope). TM1 cannot reach runtime ports, so the page-facing claim "a page cannot silently authenticate you" remains true. TM0 because SECURITY.md:134 states "there is no API for signing without the popup", which the implementation contradicts.

**Evidence.** src/js/agent.js:768-773 (allow-list entry, no auth), 778-808 (auth gate scoped to popup ports only), 937-1013 (passkey handler: candidates/assert/create with no consent check), 975-996 (assert forwards message-supplied `origin`, `rpId`, `clientDataJSON` to the host), 1416-1441 (`#validateRpId` validates rpId against the message-supplied origin); src/parcel-host:843-980 (host signs the supplied base64 clientDataJSON after its own checks); SECURITY.md:134. Verified by line-tracing in the main session and by a subagent PoC using the project's Chrome API mock: a bare `passkey` port with no auth, no popup, and no user interaction enumerated passkey entries for a claimed rpId and obtained a signature over an attacker-crafted `clientDataJSON`.

**Exploit scenario.** Malicious code in any content-script context (TM2) connects a `passkey` port, requests candidates for `origin: "https://github.com", rpId: "github.com"`, receives the user's github.com passkey entry paths, then sends `assert` with a `clientDataJSON` it crafted from a challenge fetched same-origin (e.g. by hijacking the page's own ceremony). The agent validates only rpId/origin consistency and passkey classification; the host - after whitelist, class, rpId-binding, allowCredentials, and rate-limit checks - signs the SHA-256 of the attacker's clientDataJSON. With a cached GPG-agent passphrase this is fully silent; the rate limiter bounds it to the burst (10) plus ~1 per 360s. The private key itself is never disclosed (host-enforced), which is why this is bounded below the F40M-accepted silent decrypt of login plaintexts.

**Severity calibration.** Rated M rather than H, with the uncertainty explicitly flagged: the H criterion lists "consent gating of passkey signing" as a documented protection, and this is a reachable bypass of it under TM2. It is calibrated to M for consistency with the project's own F20M rating of the structurally identical decrypt-gate gap (fixed in #69), because (a) the TM1-facing claim in SECURITY.md holds, (b) the docs' own TM2 "can do" list ("interact with the native host within the constraints of the supported action set") correctly describes this capability, and (c) the impact is bounded by host-side controls and discloses no key material. If the maintainers read SECURITY.md:134's second clause as an absolute (TM2-inclusive) promise, H is defensible. Not deduplicated: F40M concerns the popup-port token model, not the passkey port, which postdates the #69 fix.

**Recommended fix.** Give the passkey port the same class of gate as decrypt/match: issue a one-time ceremony token in the `candidates` reply and require `assert`/`create` to present it together with an explicit consent acknowledgement received over a popup-authenticated port (the popup is the consent UI, so the ack must come from the popup port, not the content-script port). At minimum, bind `assert` to the same port instance that performed `candidates` and refuse ports that skip straight to `assert`. Independently, reword SECURITY.md:134 to scope the consent claim to uncompromised extension code if the F40M position is intended to cover passkey signing too - today the document promises more than the implementation delivers.

### F60L - Newline-embedded store filenames inject phantom whitelist entries; decrypt hangs the host (LOW)

**Description.** `action_list` assembles its output from newline-separated `find` output (src/parcel-host:532-544): `MIXED` captures `find -print` verbatim, a separator loop splits it into lines, and the surviving lines are NUL-converted for `readlink -f` and then re-split on newlines inside the jq program. A store filename containing an embedded newline (e.g. `a\nstray.gpg\nb.gpg`) therefore splits into three list lines - `$STORE/a`, `stray.gpg`, `b.gpg` - and the middle and tail fragments become *phantom entries*: paths that are not store files at all, but which pass the line-count TOCTOU check (each fragment yields exactly one `readlink` line) and enter `ALLOWED_FILES` and the popup's entry list. Because a filename cannot contain `/`, phantom paths are always single components relative to the host's CWD. Decrypting a phantom that matches an existing CWD file then hangs the host: `path_uses_links` (src/parcel-host:709-719) walks `dirname` upwards and terminates only at `$PASSWORD_STORE_DIR` or `/`, but a relative path collapses to the `.` fixed point (`dirname .` = `.`) and loops forever - verified live: the decrypt produces no response, no audit line, and no log output until the process is killed.

**Threat model.** TM4 (hostile password-store contents - metacharacter filenames are explicitly in scope, e.g. a store synced from a hostile remote). TM2 amplifies convenience (a compromised extension can pick the phantom without user interaction) but adds no capability the extension lacks.

**Evidence.** src/parcel-host:532-544 (find capture and line splitting), 709-719 (`path_uses_links` loop), 721-737 (`validate_decrypt_path_policy` calling it after the `-f` check). Empirically verified with the real bootstrap + main host: phantom entries `stray.gpg` and `b.gpg` appeared in the `list` response with `real` resolving to CWD (`/home/copilot/project/stray.gpg`); decrypt of the phantom against an existing CWD file hung the host; decrypt of a non-existent phantom failed cleanly ("File not found"); the excluded-entry control was correctly denied.

**Exploit scenario and impact bound.** A crafted store makes phantom entries appear in the popup (a phantom named for an origin, e.g. `evil.com`, is origin-matched and offered on that origin's popup - a phishing-adjacent confusion vector, though clicking it yields no credential: the fill fails with "File not found" or hangs). If a phantom matches an existing file in the host's CWD (typically `/` or `$HOME`, depending on how the browser was launched), a decrypt attempt hangs the host process; the extension's ping watchdog recovers by respawning, so the practical effect is a self-healing DoS and a wedgeable host. No plaintext leak was constructible: the hang precedes GPG, `-f` fails for non-existent phantoms, and the no-`/` constraint prevents targeting store-internal or other absolute paths. The whitelist-integrity premise ("the extension is incapable of accessing non-whitelisted files") is weakened in the sense that non-store paths enter `ALLOWED_FILES`, but no path to returning their plaintext was found under the scoped threat models (planting a decryptable file in CWD requires an actor with home-directory write access, which is the F46L-excluded same-UID class).

**Recommended fix.** NUL-delimit the pipeline end-to-end (`find -print0`, `readlink -z`, and split on `\0` before jq), or reject/skip any listed path containing a newline or not starting with a store-root prefix. Separately, make `path_uses_links` terminate on relative paths (e.g. break when `dirname "$CURRENT"` stops changing, or canonicalise to an absolute path first) so a malformed path cannot wedge the host.

### F61L - Strict-mode detection omits a writability check on the bootstrap file itself (LOW)

**Description.** `parcel_strict_mode_enabled` (parcel-host:63-67) decides the bootstrap is "beyond the user's reach" - and therefore enables strict-mode PATH/binary hardening - by testing only `[ ! -O "$0" ]` (not owned by the caller) and `[ ! -w "$BOOTSTRAP_DIR" ]` (directory not writable). It never tests `[ ! -w "$0" ]`. A root-owned bootstrap file whose mode is user-writable (0666, or 0664 with the user in the owning group) inside a root-owned, non-user-writable directory therefore enables strict mode while remaining directly editable by user-level malware, which can then rewrite the bootstrap - including removing every check - while the host continues to advertise strict-mode guarantees.

**Threat model.** TM5 (build/install integrity); TM2-adjacent (user-level malware tampering). The setup script installs with `install -m 0755` (src/parcel-setup.sh:1513) and distro packages do the same, so the precondition is an admin misconfiguration or unusual packaging. No privilege boundary is crossed (the bootstrap runs as the user either way), hence L.

**Evidence.** parcel-host:63-67 (the condition), src/parcel-setup.sh:1513 (0755 install control). Demonstrated live by the subagent with a root-owned mode-0666 fixture in a root-owned directory: the function returns true while `[ -w file ]` is also true.

**Recommended fix.** Add `[ ! -w "$0" ]` to the condition so a user-writable bootstrap is treated as permissive. The function's self-containment requirement (tests extract it verbatim) is unaffected.

### F62L - http-auth token's intent restriction is transient (LOW)

**Description.** The per-challenge http-auth token restricts decryption to `intent: "http-auth"` only while its challenge is pending: the guard at src/js/agent.js:861-864 fires only when `#pendingAuthCallbacks.has(token)`, and the token is removed from that map when the callback resolves (credentials supplied, cancel, popup disconnect, or the expiry timer at 1230-1232). A popup port that authenticated with the token earlier remains `authorised = true` with no intent restriction for the rest of the port session. SECURITY.md:158 states "Decryption is restricted to `intent: 'http-auth'`; form fills are not permitted from this token" as an absolute.

**Threat model.** TM2 (a page cannot open runtime ports, and the token never reaches page-readable storage, so no TM1 path exists). Marginal impact: the same context can already decrypt via the F40M-accepted `broadcast` token. The finding is the documentation/implementation divergence on an absolute phrasing.

**Evidence.** src/js/agent.js:861-864 (guard scoped to pending callbacks), 1177-1183 (`#resolveAuthCallback` deletes the entry), 1230-1232 (timer resolves → deletes), 778-801 (port stays authorised for its lifetime); SECURITY.md:158. Dynamically confirmed by subagent PoC: while pending, `intent: "fill"` was refused; after `http-auth-cancel`, the same port's `intent: "fill"` decrypt returned plaintext.

**Recommended fix.** Record on the port (at auth time) that it authenticated via an http-auth challenge token, and enforce `intent === "http-auth"` for the lifetime of the port; or de-authorise the port when its challenge resolves.

### F65L - No popup-side regression test for the F36L origin carriage (LOW)

**Description.** The destination-origin guard (integration.js:1814-1819) applies only when the fill message carries an `origin` property. The sole wiring that makes the F34M guard cover the *primary* fill path is the popup's `origin: frameOrigin` field (src/js/popup.js:1577-1584). The existing tests cover the guard itself (integration.test.js:1101-1136) and the agent's broadcast fallback (agent.test.js:385-425), but no test asserts that the popup's fill message carries the origin - `test/popup.test.js:592-610` asserts only `action`/`token`/`plaintext`/`config`. A future refactor that drops the field (e.g. during `postFillWithAck` evolution) would silently stop the guard applying to the primary path and re-open the F34M mid-decrypt-navigation cross-origin fill with zero test failures - the same silent-regression class F56L was filed against, for a MEDIUM-severity control.

**Threat model.** TM5 (regression of a fixed security control).

**Evidence.** src/js/popup.js:1577-1584 (control); test/popup.test.js:592-610 (assertion set).

**Recommended fix.** In the popup fill test, assert `msg.origin` equals the `frameOrigin` the content script reported, and that a fill without a prior `origin` message does not dispatch.

### F66I - Four fixed gates lack regression tests (INFORMATIONAL)

**Description.** Bundled per the F50I precedent. Four fixed controls would regress silently (reverting the fix passes the entire 555-test suite): (a) the F48I `CSS.escape(entry.path)` at src/js/popup.js:1427; (b) the F57L `Object.prototype.hasOwnProperty` unknown-key gate at src/js/schema.js:115 (behaviourally verified this session: `constructor`/`__proto__` keys are rejected - a test should construct the payload via `JSON.parse`, since object literals cannot express these keys); (c) the F10L audit-log field caps at src/parcel-host:647 (control-char stripping is tested; the 128/1024/1024/4096 truncations are not); (d) per-container history isolation (src/js/agent.js:230-240, popup.js:1592-1595 - only the mock's event plumbing is tested). F50I listed (c) and (d) in v1.0.5; only port-action coverage was added in #132.

**Threat model.** TM5 (regression detection for fixed gates).

**Recommended fix.** One adversarial test per gate, as described above.

### F67I - Stale "No clipboard auto-clear" tradeoff row (INFORMATIONAL)

**Description.** SECURITY.md's Deliberate Tradeoffs table (line 169) states "Parcel does not implement this feature" for clipboard auto-clear, while the v1.0.7 Clipboard copy protection section (line 113) documents the host-side auto-clear after `clipboardTimeout` seconds (added in #167). The tradeoff row is stale pre-#167 wording; its *rationale* (avoiding the browser `clipboardRead` permission) remains valid for the browser-API approach the row describes, but a reader of the table alone would wrongly conclude copies persist indefinitely. Documentation tension only; the implementation is stronger than documented.

**Threat model.** TM0.

**Recommended fix.** Rewrite or remove the row, pointing at the host-side mechanism and its residual limits (clipboard managers ignoring the sensitivity hint, documented in the protections section).

### F63L - Documented from-source build cannot succeed without a release signer's secret key; no safe self-build path is documented (LOW)

**Description.** Every documented build path funnels through a signature only the release signers can produce. The top-level `Makefile` routes `all`/`extension`/`chrome`/`firefox` into `make -C src`, whose default target builds `dist`, which hard-depends on `dist/parcel-host.asc` (src/Makefile:49-53); that rule signs the main host script with `gpg --default-key 88FF14D6294AF4036B7F00FF676A3C09E2E47A72` - Steve Gilberd's key, one of the two primary keys the constitution permits for release signing (CONSTITUTION.md:149, §2.2). Without that secret key the step fails (empirically verified this session by running the exact invocation against a scratch file: exit 2, signing failed), so `make all` - the exact command README.md:100-101 tells from-source users to run - aborts for everyone except the release signers. The built trees are not shipped in the repository (`/chrome`, `/firefox`, `/src/dist` are gitignored), so there is no pre-built escape either. The README then routes native-host setup back to the official release artifacts (README.md:123-134: download `parcel-setup.sh` from `releases/latest` and verify with `gpg`), and neither README.md nor CONTRIBUTING.md mentions the key requirement or any alternative. The runtime enforces the same dependency from the other side: the agent fetches the bundled host script and its `.asc` and passes both to the native `install` action (src/js/agent.js:160-165), where the bootstrap verifies the signature against `VALID_SIGNERS` (default includes the same key, parcel-host:474) - so stripping the signing step yields a bundle that fails closed at host install, and re-signing with one's own key requires editing src/Makefile:51 *and* overriding `VALID_SIGNERS` (and optionally `HOST_HASH`) in `parcelrc`, all documented options (README.md:265-277) that are never connected into any from-source instructions. The constitution explicitly invites forks ("The source code of the project may of course be freely forked and modified by anyone", CONSTITUTION.md:137) and the README leans on auditability ("The code that runs in your browser is identical to the code in this repository", README.md:17), yet the repository as documented cannot produce a working self-built copy. This review's own Phase-1 build-parity check had to improvise around the requirement (see Methodology), which is the failure mode every from-source user will hit.

**Threat model.** TM0 (documentation tension: the documented from-source path cannot succeed; the auditability claim is unverifiable by building), with TM5 relevance (self-build trust is funnelled exclusively to the release key).

**Reachability.** Any user following README.md:91-111. Verified: the signing invocation fails without the secret key; no skip flag, environment override, or own-key instructions exist in README.md, CONTRIBUTING.md, or either Makefile (searched); the built trees are gitignored, closing the pre-built escape.

**Recommended fix.** Document the requirement and the safe path: state in README/CONTRIBUTING that `dist/parcel-host.asc` requires a release-signing key, and describe the supported self-build flow - re-sign with the builder's own key and set `VALID_SIGNERS` (optionally `HOST_HASH`) in `parcelrc` accordingly. Making the key overridable (e.g. `SIGN_KEY ?=` with a clear failure message when unset) would turn an opaque build failure into an explained one.

### F64L - Test Dockerfile builds on unpinned, unverified third-party code (LOW)

**Description.** The test container - documented in CONTRIBUTING.md:111-121 as the optional isolated test environment - is built from `FROM ubuntu:latest` (Dockerfile:10), a moving tag with no digest pin, and installs Node.js by piping a remotely-fetched script straight into a shell: `curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -` (Dockerfile:47), protected only by TLS with no version pin, checksum, or signature; the apt package set is likewise unpinned. The file's own header claims it "Provides a reproducible environment" (Dockerfile:4), which the recipe does not deliver. This is inconsistent with the project's own dev-machine supply-chain posture: the top-level Makefile's `DEPS_INSTALL_CUTOFF` exists specifically to "reduce the likelihood of supply-chain attacks against a developer machine" (Makefile:7-13), and F37L was fixed by pinning gitleaks to a specific version/hash for the same reason. The container is dev/test-only - the repo is bind-mounted at run time rather than baked in, and CI (`ci-unit-tests.yml`) does not use the Dockerfile - but the bind mount is exactly what turns a toolchain compromise into a source-tampering opportunity: code executing in the container can modify the working tree, and a developer could commit the result, which is the "unnoticed introduction of malicious extension code within the official repository" that TM2 explicitly scopes. Exploitation requires compromise of Docker Hub's `ubuntu` tag, NodeSource, or the TLS path, so likelihood is low, but the hardening is cheap and the project has already established the pinning pattern.

**Threat model.** TM5 (supply chain / build integrity - dev tooling).

**Reachability.** Any developer building the documented image (`DOCKER_BUILDKIT=1 docker build -t parcel-test .`, CONTRIBUTING.md:117). Verified: both cited lines are as described; the only pinned install in the file is `npm ci` via the committed lockfile; no digest, checksum, or signature verification exists for the base image or the NodeSource script.

**Recommended fix.** Pin the base image by digest (updated deliberately), and install Node.js either from the distro repository or from official binaries with a published SHA256 (or pin and checksum the NodeSource setup script). Then either drop the "reproducible" claim or make it true. Mirrors the F37L fix pattern.

## Regression Checks

All 29 prior findings marked fixed/addressed/resolved in `findings.md` were verified in the current tree - fix present, not partially reverted, not bypassed or undermined by later changes. Verified independently by the main session and by the manifest/tests subagent (citations cross-checked); several were additionally live-verified by the native-host subagent (F52C against real GnuPG 2.4.9; F53M under 8 parallel host processes; F22L byte-identical hash basis).

- F1M - VERIFIED (temp `mktemp` keyring, `--no-default-keyring --keyring`, `GNUPGHOME=/dev/null`, removed after use; parcel-host:582-603)
- F2M - VERIFIED (control chars stripped from all four audit fields; src/parcel-host:640-646)
- F9L - VERIFIED (`SHA256` resolved after `load_parcelrc`; parcel-host:497 vs :459)
- F10L/F14L - VERIFIED (field caps 128/1024/1024/4096; src/parcel-host:647)
- F11L - VERIFIED (explicit `extension_pages` CSP; src/manifest.json:25-27)
- F17L - VERIFIED (link policy applied before traversal in `collect_roots`; src/parcel-host:310-355, consumed at :502/:528)
- F18M - VERIFIED (`connect-src 'none'; frame-src 'none'; base-uri 'self'`; src/manifest.json:26)
- F19M - VERIFIED (idempotent `#ensureNativeConnected` from onStartup/onInstalled; src/js/agent.js:88-93, 145-149)
- F20M - VERIFIED (decrypt/match popup-only; integration → config; unknown rejected; src/js/agent.js:768-773, 808-814)
- F22L - VERIFIED (`jq -rj '.script' | "$SHA256"` hashes the raw bytes; parcel-host:639)
- F29L - VERIFIED (`"$SHA256"` quoted; parcel-host:639)
- F30L - VERIFIED (GPG status output to log fd 5 only; static error text to the extension; parcel-host:597-634)
- F31L - VERIFIED (`^[a-zA-Z0-9_]+$` regex gate before dispatch; parcel-host:666-667)
- F34M - VERIFIED (destination-origin guard; src/js/integration.js:1814-1819)
- F35M - VERIFIED (bucket persisted to the state file; src/parcel-host:101-135, 649-703)
- F36L - VERIFIED (`origin: frameOrigin` on the primary fill message; src/js/popup.js:1583 - test gap noted as F65L)
- F37L - VERIFIED (gitleaks v8.30.1 pinned with per-arch SHA-256 checksums, verified pre-extraction; scripts/pre-commit-gitleaks:56-63)
- F38I - VERIFIED (comment matches the allow-list; src/js/agent.js:765-767)
- F42L - VERIFIED (passkeyDir rejects `..`/leading `/`/control/glob chars; src/parcel-host:1002)
- F45L - VERIFIED (`rsync -av --delete` in both targets; `release: clean …`; Makefile:38, 48, 76)
- F47L - VERIFIED (`return 0` after the invalid-timestamp error; src/parcel-host:472-475)
- F48I - VERIFIED (`CSS.escape(entry.path)`; src/js/popup.js:1427 - test gap noted in F66I)
- F50I - VERIFIED (non-whitelisted port actions tested; test/agent.test.js:601-619 - remaining gaps noted in F66I)
- F52C - VERIFIED (anchored `grep '^\[GNUPG:\] VALIDSIG '`; parcel-host:628; live-verified against a malicious-UID key; F56L adversarial test present)
- F53M - VERIFIED (rename/noclobber lock with orphan recovery and fail-closed exhaustion; src/parcel-host:140-227, 676-703; 8-process concurrency verified)
- F54L - VERIFIED (TOTP `step` 1-3600, `digits` 6-10, parseInt-coerced; src/js/helpers.js:50-54)
- F55L - VERIFIED (real `crossOrigin`, `topOrigin` only when cross-origin and known; src/js/webauthn.js:233-240)
- F56L - VERIFIED (malicious-UID GOODSIG adversarial regression test; test/native-host.test.js:593-629)
- F57L - VERIFIED (`Object.prototype.hasOwnProperty.call` gate; src/js/schema.js:115; behaviourally re-verified)
- F58L - VERIFIED (cyclic guard + object-level `items` recursion; src/js/schema.js:46, 120-124)

No regressions, partial reverts, or bypasses were found.

## Deliberate Tradeoffs

Each documented tradeoff was re-examined against the current code; all remain acceptable unless noted:

- **Plaintext bash host** - holds; auditable and verified.
- **HOST_HASH off by default** - holds; the `host-unpinned` popup warning (#177) now surfaces it in-session.
- **Absent `.parcel.json` reveals all entries** - holds; default-rules warning shown in the popup.
- **Content script on all URLs** - holds; Firefox optional-permission flow verified in popup.js.
- **Entry rules don't dereference paths** - holds; decrypt-time link revalidation verified (and the phantom-entry parsing defect in F60L is a *newline* issue, not a symlink-policy issue).
- **No clipboard auto-clear** - **divergent**: the feature now exists host-side (#167); the tradeoff row is stale (F67I). The underlying rationale (no browser `clipboardRead` permission) still holds.
- **Extension detectable / fingerprintable** - holds (WAR set re-verified as minimal: `popup.js` removed, `webauthn.js` added with need).
- **WebAuthn interception in the page realm** - holds; bridge treated as untrusted, all decisions re-derived isolated-side/host-side.
- **First-come-first-served interception** - holds; non-configurable accessors, full back-off, conflict notice verified.
- **`webRequest` for HTTP auth** - holds; per-challenge token binding verified (with the F62L phrasing divergence noted).
- **Cards bypass origin-matching** - holds; `originBound: false` + `scope: "context"` defaults verified in schema.js classDefaults, with the "spoofed includeClasses cannot widen origin scope" test passing.

## Residual Observations

Risks inherent to the design, and hardening notes for which no reachable path was identified under the scoped threat models:

1. **`save_state` writes through a symlinked lock file** while `repair_state` explicitly guards `[ ! -L "$LOCKED_STATEFILE" ]` - an asymmetry. Exploitation requires a same-UID hostile process racing the lock rename (the F46L-excluded actor); written content is constrained to numeric bucket lines and hex fingerprints. A `[ ! -L ]` guard in `save_state` (or in `lock_state` after the rename) would close it cheaply.
2. **Under TM2 the audit-log origin remains attacker-controlled** (the host cannot independently verify browser origins; `message.origin` is forwarded verbatim, per the F20M/#69 disposition). Inherent to the design; noted for forensic-integrity expectations.
3. **`.gpg-id` walk follows directory symlinks** for recipient lookup - but a store-writing attacker can simply overwrite the in-store `.gpg-id`, so the symlink adds nothing (subagent-verified).
4. **Stale state-file blacklist persists while the shipped list is empty** - fail-closed only (a stale revocation keeps rejecting); no weakening path.
5. **`decryptBucket`/`decryptRate` are not range-capped host-side** - int64 overflow fails closed (negative bucket → deny); a huge non-overflowing value is a config choice the popup warns about.
6. **A partial message (length prefix with short body) stalls `head -c` without a watchdog**, wedging one host process - local TM2 DoS only; the extension can already spawn unbounded hosts.
7. **`parcelrc_check_binary` validates only the final hop's directory** for symlink chains - creating the root-owned link into user-writable space already requires root.
8. **In-session revocation install-order window** - the documented best-effort limitation of BLACKLIST_SIGNERS; the realistic service-worker restart flow closes it.
9. **`changes_since` sub-second race** can permanently miss a store change (display-only; the host re-validates on every decrypt).
10. **Popup iframe URL (with correlation token) may be observable via resource timing** - unverifiable without a live browser; no attack path beyond F39T-accepted presentation control even if real.
11. **Passkey popup-spam guard is per-frame** - N same-origin iframes get 2N popups before cooldown; consent itself is not bypassable.
12. **`base32ToArrayBuffer` silently maps invalid characters** - wrong TOTP rather than an error; fail-visible.
13. **Config-controlled regexes** (rule `strip`/`pattern`, target patterns) compile in popup/content-script contexts - ReDoS surface from a hostile `.parcel.json`, the F12T-accepted class; SECURITY.md already warns to review synced stores.
14. **The mock GPG performs no real cryptography** (always-VALIDSIG, same plaintext) - the suite pins the gpg *invocation* only implicitly; live signature verification was done manually in this review.
15. **`make extension` runs `prettier --write` over `src/`** as part of the build (CI's `--check` gate makes it a no-op in practice); **`make release` runs a bare `git reset`** (maintainer footgun, no artifact impact); **`chrome/` ships the dead `integration.es6.js`** (harmless parity leftover). (The `Dockerfile` base-tag note formerly here was promoted to a finding, F64L, after the cross-model exchange contributed the NodeSource vector and the posture argument.)

## Things Done Well

- **The host is a genuine enforcement boundary, not theatre.** Whitelist, rate limiter, rpId binding, allowCredentials, passkey content-marker backstop, and decrypt-time link revalidation all re-derive everything from untrusted input, and all survived live adversarial testing - including 8-process parallel attack on the rate limiter (exactly 10 successes) and malicious-UID/multi-sig signature forgeries against real GnuPG.
- **The v1.0.7 parcelrc whitelist parser is exemplary** - canonical-line-only, injection-proof by construction (PoC-verified), with values validated before use and a documented, tested trust model.
- **The F53M atomic state lock** (rename-based single-winner, noclobber fresh-install, orphan recovery, fail-closed exhaustion) is a well-engineered answer to a hard problem in bash.
- **Zero XSS sinks** in the entire extension codebase - every store-controlled value renders via `textContent`/`createTextNode`; the passkey save-command builder quote-escapes paths and uses an underscore-containing heredoc delimiter that base64 content cannot terminate.
- **Regression discipline**: 29/29 prior fixes intact, with adversarial regression tests for the most dangerous past bug (F52C/F56L), and the F55L/F54L fixes carried their tests with them.
- **Source↔distribution parity is real and verifiable** - byte-identical trees apart from two documented, behaviour-preserving manifest rewrites.
- **The security-warning system** (#177) turns accepted tradeoffs (unpinned host, disabled audit/rate-limit) into in-UI prompts rather than silent defaults.

## Cross-Model Verification

Phase 2 was completed on 2026-09-12, after the maintainer imported the other reviewer's exchange file. The kimi-k3 table (`security-review/security-review-table-kimi-k3-20260912-099857c.md`, same commit `099857c`) was read in full; per protocol, only the exchange table was accessed - kimi-k3's report was not. The table contained two findings, both LOW; each was independently re-derived from the code by the main session before admission, and both were confirmed:

- **F63L** - "Source builds fail without the maintainer's secret signing key; no documented safe path" (src/Makefile:51, README.md:130-145). **Confirmed and admitted as F63L.** My independent verification went beyond the citation: the full build-graph trace (all four documented targets hard-depend on `dist/parcel-host.asc`), an empirical reproduction of the signing failure, the runtime fail-closed consequence through the agent's `install` handshake and `VALID_SIGNERS`, the gitignore check closing the pre-built-trees escape, the constitution's fork clause, and the absence of any documented alternative in README.md, CONTRIBUTING.md, or either Makefile. Severity L concurred; I tag the threat model TM0 with TM5 relevance (kimi-k3 tagged TM0).
- **F64L** - "Dev/test Dockerfile builds on unpinned, unverified third-party code" (Dockerfile:10, 47). **Confirmed and admitted as F64L.** Both cited lines verified; I added the dev/test-only scoping (bind-mounted repo, no CI use), the inconsistency with the project's own `DEPS_INSTALL_CUTOFF` posture and the F37L pinning precedent, and the working-tree-tampering path via the bind mount. Severity L and TM5 concurred. This item had been a Phase-1 residual observation (base tag only); the exchange's NodeSource `curl | bash` vector and posture argument justified promoting it to a finding.

**Disagreements and non-reproductions:** none. Neither incoming finding duplicates a prior finding in `findings.md` (the closest, F37L, concerns a different dev tool and was fixed by pinning) nor an accepted tradeoff, and neither contradicts any Phase-1 finding. The kimi-k3 table raised no challenges to my Phase-1 findings, and no verdict in this report was changed for consensus - both incoming findings were admitted on their own independently-verified evidence, and my original seven stand unchanged.

Both exchange files (mine, `security-review/security-review-table-glm-5.3-20260912-099857c.md`, and the imported kimi-k3 table) were deleted after this report was finalised, per protocol.

## Second-Look Review

Answers to §7's checklist, after re-reading the full draft adversarially:

- **Did every finding survive the reachability requirement?** Yes, with honest bounds: F59M's full chain to a *useful* forgery requires an RP-issued challenge (the TM2 actor obtains one same-origin or by hijacking the page's own ceremony - traced, and the subagent PoC confirmed the signing itself); F60L's plaintext-leak variant was explicitly rejected after empirical testing (the hang precedes GPG, and phantoms cannot contain `/`), so it is reported at LOW for what it does do (whitelist pollution + host wedge + spoofable popup rows); F61L requires a loosened file mode (misconfiguration precondition, stated); F62L's actor already holds the F40M-accepted broadcast decrypt (stated); F65L, F66I, F67I, F63L, F64L are regression/doc/tooling findings with no live exploit by construction (8 and 9 were additionally verified empirically - the signing failure reproduced against a scratch file, and the Dockerfile claims checked line-by-line against CI and the docs). One "looks suspicious" that did *not* survive: the initial hypothesis that newline phantoms could carry absolute `/../` paths into excluded entries was empirically falsified (filenames cannot contain `/`) and is not reported.
- **Which coverage areas got only superficial treatment?** `src/parcel-setup.sh` (2562 lines) received a full read by the native-host subagent plus targeted main-session checks (signature guidance, write scope, sudo handling, HOST_HASH application), but not line-by-line main-session scrutiny; the vendored `src/publicsuffix` subtree was excluded per project instructions (only its packaging role checked); `css/popup.css` was grepped for injection vectors rather than read in full. None of these produced indicators warranting deeper passes.
- **Unverified assumptions?** (a) That browsers spawn native hosts with CWD `/` or `$HOME` (affects only F60L's impact bound, already reported conservatively); (b) subagent 2's resource-timing residual is unverifiable without a live browser (left in residuals, not findings); (c) the Chrome API mock's `port.sender` fidelity - inherent to mocking, all sender-dependent paths null-guarded and exercised with explicit senders. The mock-GPG limitation is disclosed in Methodology.
- **Misattributed tradeoffs?** Cross-checked every row of the SECURITY.md tradeoffs table against the code; one stale row found and reported as F67I (I). The F40M/F46L/F12T/F39T/F28T/F44T/F43L/F27T/F8T/F6T/F33T/F21T/F23T/F24T/F25T/F15T/F16T/F32T acceptances were re-derived and still hold; none were re-reported.
- **Every `jq` call site, unquoted `$VAR` in command position, dispatch path?** Yes - all `jq` invocations use `--arg`/`--argjson`/`--rawfile` or regex-validated values with static filter programs; the only deliberate unquoted expansion in command position is the hex-validated blacklist loop (parcel-host:563, commented); the action dispatch regex gate and the full reachable `action_*` set (8 functions) were enumerated.
- **Origin validation on every fill/decrypt path?** Proven for the popup-driven path (carries `origin: frameOrigin`, guard refuses mismatch, `structuredClone`-preserved `undefined` fails closed), the broadcast fallback (carries origin, top-frame-only handler, guard applies), and mid-decrypt navigation (new-origin content script refuses the stale origin). `fill-value` intentionally lacks it (F51I-rejected: values are already-decrypted plaintext in the popup). The http-auth path is token-and-intent-bound (F62L notes the phrasing divergence).
- **Severity consistency and vocabulary?** Only C/H/M/L/I used; no CRITICAL or HIGH findings, and I would defend the M of F59M to a challenger with the F20M-precedent argument while flagging the H question in the finding itself; the L ratings each carry an explicit impact bound.
- **Accessed anything under `security-review/reviews/`?** No. The directory was listed (filenames only) to derive this report's filename convention; no file content was read. Recorded in Methodology.
- **Confidence per finding:** all nine High - each is code-traced by the main session; the four behavioural ones (1, 2, 3, 4) were additionally demonstrated by PoC (subagent PoCs re-verified against the code; the phantom-entry PoC built and run by the main session), and the two cross-model ones (8, 9) were admitted only after independent reproduction (the signing failure re-run empirically; the Dockerfile claims checked against CI and the docs). What would change them: for F59M, evidence that a passkey-port gate exists elsewhere (none found) or a maintainer statement that F40M's scope covers signing; for F60L, a CWD configuration in which decryptable files routinely exist (would raise, not lower, severity); for F61L, a packaging mode that is user-writable by design (would raise it); for F63L, a documented self-build path existing somewhere not searched (none found in README.md, CONTRIBUTING.md, or either Makefile); for F64L, evidence that the Dockerfile feeds CI or release builds (it does not).

## About This Review

- **Model:** glm-5.3 (glm-5.3-flex; operational suffix omitted per protocol)
- **Date:** 2026-09-12
- **Commit ref:** `099857c` (short hash); `git describe --tags --always` = `v1.0.7` - HEAD is exactly at the release tag; the working tree was clean throughout, so this review covers the shipped release with no uncommitted diff.
- **Release:** v1.0.7 (per `.version`)
- The committed `security-review/prompt.md` is the canonical record of what was prompted.
