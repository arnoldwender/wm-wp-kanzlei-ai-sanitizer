# WM Kanzlei AI Sanitizer — Developer Manual

> Measured against the code in this repository (2026-09-15). It replaces `docs/DEVELOPER-GUIDE.md`, which listed three of the five routes.

---

## 1. Layout

| Path | Role |
| --- | --- |
| `wm-kanzlei-ai-sanitizer.php` | Header, constants (`WM_KANZLEI_VERSION`, `_FILE`, `_PATH`, `_URL`), PSR-4-style autoloader for `WMCyber\Kanzlei\` → `includes/`, activation (tables) and `wp_initialize_site` Multisite sub-site table creation, hub registration on `wm_register_suite_module`, boot on `plugins_loaded`. |
| `includes/Core/Plugin.php` | Text domain, `RequestShield::inspect_globals()`, REST routes, admin screen, WP-CLI. |
| `includes/Core/Settings.php` | The seven switches in `wm_kanzlei_settings`; `enabled_types()`, `save_switches()` (keeps keys it does not know), `enable_all()`. |
| `includes/Sanitizer/NerEngine.php` | `detect_entities( $text, ?$types )`, `TYPES`, `iban_checksum_ok()`, `longest_valid_iban()`, `steuer_id_checksum_ok()`, `collect_review_warnings()`. |
| `includes/Sanitizer/TokenVault.php` | `tokenize()`, `rehydrate()`, `is_valid_mapping()`, `PLACEHOLDER_PATTERN`. |
| `includes/Audit/AuditChain.php` | `append()`, `verify()`, `record_hash()`, `seal()`, `TIP_OPTION`. |
| `includes/API/RestController.php` | Five routes under `wm-kanzlei/v1`. |
| `includes/Admin/AdminDashboard.php` | Menu, family sheets (plugin page and dashboard), widget, tabs, simulator (with inline `notice-warning` review hints), settings actions (`register_setting` for opt-in uninstall). |
| `includes/Integrations/EcosystemBridge.php` | WP 6.5+ Block Bindings (`wm-kanzlei/stats`) and GenerateBlocks 2.x Dynamic Tag (`{{wm_kanzlei_stat}}`). |
| `includes/CLI/KanzleiCommand.php` | `wp kanzlei sanitize`; `report()` and `mask()` without WP_CLI. |
| `includes/Adapters/Kanzlei_Spoke_Adapter.php` | WM Suite Hub contract. |
| `includes/Security/RequestShield.php` | Reports null bytes and stream wrappers in request values via `wm_sentinel_security_incident` (and `error_log` under `WP_DEBUG`); does not block. |
| `includes/Database/Schema.php` | `dbDelta` for the two tables (`activate( bool $network_wide = false )` iterates Multisite sites when network-activated). |
| `uninstall.php` | Preserves options and tables by default; removes options, tables and the old vault directory only when `wm_kanzlei_delete_data_on_uninstall` is enabled. |
| `languages/` | 28 translated `.po`/`.mo` catalogs and `wm-kanzlei-ai-sanitizer.pot`; see §9. |

---

## 2. Detection

Types, in overlap priority: `IBAN` (100), `STEUER_ID` (90), `EMAIL` (80), `AKTENZEICHEN` (70), `GELDBETRAG` (60), `PERSON_NAME` (50), `PHONE` (40). Overlapping matches keep the higher priority, then the longer match.

| Type | Pattern in words |
| --- | --- |
| `AKTENZEICHEN` | digits (1-3) or a Roman numeral (I-X, up to 5), a register of one capital and up to three letters, optionally a second one, number (1-5 digits) / year (2-4 digits); not inside a longer token |
| `IBAN` | 2 letters, 2 digits, 11-30 letters or digits with optional single spaces or hyphens, any case; cut to the longest prefix passing mod-97; a candidate that never passes is kept without trailing words if it still has 15 characters |
| `EMAIL` | local part @ domain . TLD |
| `STEUER_ID` | 11 digits starting with `[1-9]`, grouped 2-3-3-3 or not, not part of a longer number; `steuer_id_checksum_ok()` verifies BZSt § 139b AO / ISO 7064 Mod 11,10 and `collect_review_warnings()` emits `steuer_id_unverified_checksum` when unverified (still redacted) |
| `PHONE` | `+49` (optionally a space and `(0)`), `0049` or `0`, a non-zero digit, 5-15 digits, spaces, slashes, hyphens, parentheses, a final digit; not preceded by a letter, digit or `+` |
| `PERSON_NAME` | a trigger (`Herr(n)`, `Frau`, `Rechtsanwalt/-anwältin`, `RA(in)`, `Mandant(in/en)`, `Zeuge/Zeugin/Zeugen`, `Beklagte(r/n)`, `Kläger(in/s)`, `Patient(in/en)`, `Dr.`, `Prof.`), optional `Dr.`/`Prof.`, optional `von/van/de/zu/vom/zum`, 1-3 capitalised words (hyphen allowed); role nouns after the trigger (`Richterin`, `Vorsitzender`, `Kollege`, …) are not names; afterwards every bare occurrence of the last name word (3+ characters) is added |
| `GELDBETRAG` | a number with or without thousands dots and optional `,dd`, with `EUR`/`USD`/`€`/`$` before, or `EUR`/`Euro`/`USD`/`€`/`$` after |

`detect_entities()` throws `InvalidArgumentException` for text that is not valid UTF-8 and `RuntimeException` when a pattern fails (`preg_last_error_msg()`); it never returns a partial result.

---

## 3. Placeholders

`tokenize( $text, $entities, $salt )`: longest values first; placeholder `{{TYPE_` + the first 16 hex characters of `hash_hmac( 'sha256', TYPE . "\0" . value, $salt )` + `}}`, extended by 8 characters while it collides with another value in the same call; every occurrence of the value is replaced (`str_replace`). Returns `sanitized_text` and `mapping`.

`rehydrate( $text, $mapping )`: `strtr()` with the pairs whose key matches `PLACEHOLDER_PATTERN` and whose value is a string; other pairs are skipped.

---

## 4. REST

| Method | Route | Permission | Arguments | Answer |
| --- | --- | --- | --- | --- |
| `POST` | `/wm-kanzlei/v1/sanitize` | `edit_posts` | `prompt` (string, required) | 200 `{success, session_id, sanitized_text, entities_found, entity_types, types_checked, mapping, review_warnings, audit_id}`; 400 `empty_prompt` / `wm_kanzlei_invalid_encoding`; 500 `wm_kanzlei_detection_failed`; 503 `wm_kanzlei_audit_unavailable` (session or log row not written; the session row is removed again) |
| `POST` | `/wm-kanzlei/v1/rehydrate` | `edit_posts` | `response` (string, required), `mapping` (required) | 200 `{success, rehydrated_text}`; 400 `empty_response` / `wm_kanzlei_invalid_mapping` |
| `POST` | `/wm-kanzlei/v1/proxy` | `edit_posts` | — | 501 `wm_kanzlei_no_provider` |
| `GET` | `/wm-kanzlei/v1/audit-log` | `manage_options` | — | 200 `{success, total, logs (50 newest, without compliance_standard), chain}` |
| `GET` | `/wm-kanzlei/v1/certificate` | `edit_posts`, then administrators or the session's operator | `session_id` (string, required) | 200 `{record_type: session_record, session_id, created_at_utc, operator_id, entities_redacted, audit {id, action, entity_types, seal, sealed}, chain_status, note}`; 403 `wm_kanzlei_forbidden`; 404 `wm_kanzlei_unknown_session` |

---

## 5. Audit chain

Table `{prefix}wm_kanzlei_audit_log` (`id, session_id, action, entity_types_summary, compliance_standard, previous_hash, current_hash, created_at`). `append( $session_id, $action, $types, $created_at )`:

1. `SELECT GET_LOCK( 'wm_kanzlei_audit_chain', 5 )`; anything but `1` → `{ok: false}`, nothing written.
2. Head = option `wm_kanzlei_audit_chain_tip`, else the newest row with a non-empty `previous_hash`, else 64 zeros.
3. `record_hash = sha256( 'WM-KANZLEI-AUDIT-V1|' . session_id . '|' . action . '|' . types . '|' . created_at )`; `seal = hash_hmac( 'sha256', head . '|' . record_hash, wp_salt( 'secure_auth' ) )`.
4. Insert with `compliance_standard = 'NONE'`, `previous_hash = head`, `current_hash = seal`; refused → `{ok: false}`, tip unchanged.
5. Tip option = seal; `RELEASE_LOCK` in `finally`.

`verify()` walks the rows by id: a row with empty `previous_hash` before the first sealed row is unchained; after it, it is an insertion (`BROKEN`). For sealed rows `previous_hash` must equal the preceding seal and `current_hash` the recomputed seal. Then: sealed rows without a tip → `BROKEN`; tip ≠ last seal → `BROKEN` (newest rows removed); no rows but a tip → `BROKEN`; no rows, no tip → `EMPTY_CHAIN`; only unchained rows → `UNCHAINED_ONLY`; otherwise `INTACT`. Result: `{status, checked, unchained, broken_id, error}`.

---

## 6. Admin

Menu *KI-Sanitizer* (`edit_posts`, position 32), page `wm-kanzlei-sanitizer`. Tabs: `overview`, `simulator` (`edit_posts`), `settings`, `log` (`manage_options`), `help`; a tab the user may not see falls back to the overview and is not linked. Form actions on `admin_init`: `save_settings` (nonce `wm_kanzlei_save_settings`) and `enable_all` (nonce `wm_kanzlei_enable_all`), both `manage_options`, redirect after saving. The simulator (nonce `wm_kanzlei_sim`) runs the engine with the enabled types and the vault with a random salt, surfaces `collect_review_warnings()` in an inline `notice-warning` box, and stores nothing; "Beispieltext laden" fills `SAMPLE_TEXT`. Family sheets load on the plugin page and on `index.php` for the widget.

---

## 7. WP-CLI and hub

`wp kanzlei sanitize "<text>"`: checked types, values masked (`mask()`: first two characters, then `*`), replaced text; `WP_CLI::warning` when nothing was found, `WP_CLI::error` for invalid UTF-8.

Spoke adapter: health `ERROR` when a table is missing, the chain is `BROKEN` or the detection self-test fails (sample with file number, IBAN, e-mail, `Frau Dr. Schneider`, `15.000 €`); telemetry `total_sessions`, `total_entities_redacted`, `audit_records`, `audit_chain_status`, `audit_rows_unchained`, `detection_self_test`, `mapping_storage`, `outbound_requests`; actions `self_test`, `verify_chain`; settings URL `admin.php?page=wm-kanzlei-sanitizer&tab=settings`.

---

## 8. Tests

```bash
php tests/test-suite.php        # 12 groups, strict mock $wpdb that throws on unknown SQL
bash tests/run-mutations.sh     # tests/mutations.php, every entry must turn the suite red
vendor/bin/phpunit              # tests/Unit (after composer install; PHPUnit 11.5+ on PHP 8.2)
wp eval-file wp-content/plugins/wm-kanzlei-ai-sanitizer/tests/wp-runtime-kanzlei.php --user=1
```

`tests/wp-runtime-kanzlei.php` runs inside WordPress: routes through `rest_do_request()` (400, 501, 404), a real `/sanitize` call, the chain, the settings switches and the admin screen, all inside a transaction rolled back at shutdown (transaction statements of other plugins rewritten to savepoints, DDL refused, persistent object cache refused), and compares table counts and the tip option before and after.

---

## 9. Catalogs & Extensibility

`languages/wm-kanzlei-ai-sanitizer.pot` is maintained from the German source via `wp-plugin-fleet-pot-freshness.py wm-kanzlei-ai-sanitizer --write` (verified by `tests/test-pot-freshness.php`), and all 28 standard `.po`/`.mo` catalogs are compiled with `msgfmt --check-format`.

Hooks and integrations:
- Filter `wm_kanzlei_entity_patterns( array $patterns, string $text, ?array $types )`: map of uppercase entity type (`A-Z_`) to PCRE pattern collected before overlap resolution.
- Filter `wm_kanzlei_sanitized_result( array $payload, string $session_id, array $found )`: filters the `/sanitize` REST payload after session and audit rows are sealed.
- Filter `wm_kanzlei_stat_value( ?string $value, string $key )`: filters operational counters resolved by `EcosystemBridge`.
- Action `wm_kanzlei_ready( Plugin $plugin )`: fires at the end of `Plugin::boot()`.
- WP 6.5+ Block Bindings source `wm-kanzlei/stats` and GenerateBlocks 2.x Dynamic Tag `{{wm_kanzlei_stat key="replaced"}}` (`sessions`, `replaced`, `audit_rows`, `active_types`, `chain_status`).
