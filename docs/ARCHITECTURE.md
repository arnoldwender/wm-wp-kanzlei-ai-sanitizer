# Architecture — WM Kanzlei AI Sanitizer

Measured against the code on 2026-09-15. The earlier edition drew a "§ 203 StGB Zero-Knowledge Proxy" that intercepted every LLM prompt and dispatched it over "encrypted HTTPS" to OpenAI, Anthropic, Gemini or DeepSeek, an "ephemeral rehydration vault" and a "Merkle hash chain" with operator ids. None of that existed: the plugin makes no outbound request, keeps no vault, and its hashes did not chain.

## 1. Where the plugin sits

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Your application (a Kanzlei tool, a form, a script)                  │
│                                                                      │
│  1. POST /wm-kanzlei/v1/sanitize {prompt} ───────────────┐           │
│                                                          ▼           │
│                              ┌─────────────────── WordPress ──────┐  │
│                              │ NerEngine: 7 regex types           │  │
│                              │ TokenVault: {{TYPE_hex}} + mapping │  │
│                              │ sessions row + sealed audit row    │  │
│                              └────────────────────────────────────┘  │
│  2. ◄── sanitized_text + mapping (the mapping is not stored)         │
│                                                                      │
│  3. Your application sends sanitized_text to an AI service ──► ?     │
│     (the plugin is not involved and does not know which or whether)  │
│                                                                      │
│  4. POST /wm-kanzlei/v1/rehydrate {response, mapping} ──► WordPress  │
│  5. ◄── rehydrated_text                                              │
└──────────────────────────────────────────────────────────────────────┘
```

`/proxy` answers 501. Undetected values (see README, *Not shipped*) go out in clear text in step 3.

## 2. What is stored

| Table / option | Written by | Contents |
| --- | --- | --- |
| `{prefix}wm_kanzlei_sessions` | `/sanitize` | session id, user id, number of replaced values, estimated length, time (UTC) |
| `{prefix}wm_kanzlei_audit_log` | `/sanitize` via `AuditChain::append()` | session id, action, found types, `NONE`, previous seal, seal, time |
| `wm_kanzlei_audit_chain_tip` | `AuditChain::append()` | the newest seal |
| `wm_kanzlei_settings` | settings screen | the seven switches (older installs may keep unused keys) |
| `wm_kanzlei_delete_data_on_uninstall` | settings screen | opt-in flag (`'1'`/`'0'`) controlling removal on uninstall |

Nothing stores the prompt, the replaced text or the mapping. Options and both tables are preserved on uninstall unless `wm_kanzlei_delete_data_on_uninstall` is explicitly enabled.

## 3. Keys and seals

- Placeholders: HMAC-SHA256 of type and value with 16 random bytes per call (REST, CLI, simulator); the key is discarded after the call.
- Audit seals: HMAC-SHA256 with `wp_salt( 'secure_auth' )` over the previous seal and a SHA-256 of the row contents. Tamper-evident while `wp-config.php` and the tip option are out of an attacker's reach; re-sealable by database and `wp-config.php` owners; not time-stamped by any external party.

## 4. Failure behaviour

| Situation | Result |
| --- | --- |
| Text is not valid UTF-8 | `/sanitize` 400, CLI error, simulator error; nothing replaced |
| A pattern fails | `/sanitize` 500; nothing returned |
| Chain lock not obtained or insert refused | `/sanitize` 503, the session row removed, nothing returned |
| Malformed mapping | `/rehydrate` 400 |
| Table missing or chain broken | hub health `ERROR`; log tab shows `BROKEN` with the reason |

---

<!-- wm-measured-inventory -->

## Measured inventory

Regenerated from the code, never hand-edited. Everything above this line is written by hand and stays.

```bash
python3 the fleet's architecture inventory tool wm-kanzlei-ai-sanitizer --append-to docs/ARCHITECTURE.md
```

## Inventory by layer

**15 PHP files, 2464 lines** (excluding `tests/`, `vendor/`, `node_modules/`, `languages/`).

| Layer | Files | Lines |
|---|---:|---:|
| `(raíz)` | 2 | 148 |
| `includes/API` | 1 | 245 |
| `includes/Adapters` | 1 | 189 |
| `includes/Admin` | 1 | 565 |
| `includes/Audit` | 1 | 185 |
| `includes/CLI` | 1 | 87 |
| `includes/Core` | 2 | 171 |
| `includes/Database` | 1 | 71 |
| `includes/Integrations` | 1 | 158 |
| `includes/Sanitizer` | 3 | 570 |
| `includes/Security` | 1 | 75 |

---

## Classes

| Class | File |
|---|---|
| `AdminDashboard` | [`includes/Admin/AdminDashboard.php`](../includes/Admin/AdminDashboard.php) |
| `AuditChain` | [`includes/Audit/AuditChain.php`](../includes/Audit/AuditChain.php) |
| `DetectionFailed` | [`includes/Sanitizer/DetectionFailed.php`](../includes/Sanitizer/DetectionFailed.php) |
| `EcosystemBridge` | [`includes/Integrations/EcosystemBridge.php`](../includes/Integrations/EcosystemBridge.php) |
| `KanzleiCommand` | [`includes/CLI/KanzleiCommand.php`](../includes/CLI/KanzleiCommand.php) |
| `Kanzlei_Spoke_Adapter` | [`includes/Adapters/Kanzlei_Spoke_Adapter.php`](../includes/Adapters/Kanzlei_Spoke_Adapter.php) |
| `NerEngine` | [`includes/Sanitizer/NerEngine.php`](../includes/Sanitizer/NerEngine.php) |
| `Plugin` | [`includes/Core/Plugin.php`](../includes/Core/Plugin.php) |
| `RequestShield` | [`includes/Security/RequestShield.php`](../includes/Security/RequestShield.php) |
| `RestController` | [`includes/API/RestController.php`](../includes/API/RestController.php) |
| `Schema` | [`includes/Database/Schema.php`](../includes/Database/Schema.php) |
| `Settings` | [`includes/Core/Settings.php`](../includes/Core/Settings.php) |
| `TokenVault` | [`includes/Sanitizer/TokenVault.php`](../includes/Sanitizer/TokenVault.php) |

---

## Entry points

**REST routes:** `/audit-log`, `/certificate`, `/proxy`, `/rehydrate`, `/sanitize`

**WP-CLI:** `kanzlei`

---

## Persistence — who writes each key and who reads it

| Key | Written by | Read by |
|---|---|---|
| `wm_kanzlei_delete_data_on_uninstall` | `includes/Core/Settings.php` | `includes/Core/Settings.php`, `uninstall.php` |

Every key has exactly one writing layer and at least one reader.


**Tables** (prefixed with `$wpdb->prefix`): `wm_kanzlei_audit_log`, `wm_kanzlei_sessions`

---

## Gates

- `tests/bootstrap.php`
- `tests/mutations.php`
- `tests/run-mutations.sh`
- `tests/test-pot-freshness.php`
- `tests/test-suite.php`
- `tests/test-ui-family.php`
- `tests/wp-runtime-kanzlei.php`
- `.github/workflows/ci.yml`

What CI actually runs is in the workflow files above — a test file that no workflow invokes is not a gate.

---

## Drift detected against the documentation

Nothing measurable: versions agree and every class named in the documents exists.

