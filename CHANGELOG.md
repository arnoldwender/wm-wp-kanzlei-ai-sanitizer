# Changelog — WM Kanzlei AI Sanitizer

All notable changes to **WM Kanzlei AI Sanitizer** are documented in this file in adherence to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This file was created on 2026-09-15; the history before it is summarised from `git log`.

---

## [Unreleased]

### Fixed
- Relaxed `EcosystemBridge` GenerateBlocks `generateblocks_dynamic_tag_replacement` filter parameter to `mixed`.
- Renamed `RestController::NAMESPACE` to `REST_NAMESPACE` for PHP 8.5/8.6 compatibility.
- Added `Schema::maybe_upgrade()` in `Plugin::boot()` (`plugins_loaded`) with non-autoloaded `wm_kanzlei_db_version` option and opt-in cleanup in `uninstall.php`.

## [1.2.2] - 2026-11-21

### Fixed

- Screenshot 1 showed the WM Suite menu from before WM Suite Hub 1.2.3, with entries the hub no longer has («Marketplace (Lösungspakete)», «Merkle-Audit-Protokoll», «CRA- & SBOM-Zentrale»). It is retaken with the current menu; the plugin's code is unchanged.

## [1.2.1] - 2026-11-21

### Fixed

- The simulator's "Prüfhinweise" heading (above the review warnings) was untranslated in all 28 catalogs; it is translated now.
- "%d Wert ersetzt" repeated one plural form for every count above one in languages with three or more forms; Arabic, Czech, Croatian, Irish, Latvian, Lithuanian, Maltese, Romanian, Slovak and Slovenian now carry each form their plural rule needs.

### Changed

- The catalogs carry the plugin page as Plugin URI and the Author URI as the plugin header has it.

- The bundled family stylesheet is identical to WM Suite Hub 1.2.5 again: it starts the admin header below WordPress's help toggle instead of shortening it. This plugin's own screens register no help tab, so they change only where another plugin adds one.

## [1.2.0] - 2026-11-20

### Changed
- The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
- The `.wordpress-org/` banners show the current version.
- The first screenshot description (`readme.txt` and the three READMEs) names what the screen shows: the overview with its counts, what the plugin does and what it does not detect. It described a masking workbench and audit log "protecting" values before AI prompts; the simulator and the log are other tabs, and the plugin replaces values, it does not vouch for a text. The READMEs no longer list the archive among the known issues.

### Removed
- The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

## [1.1.4] - 2026-11-19

- Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.

- Added root `SUPPORT.md`, `.github/ISSUE_TEMPLATE/{config.yml,bug_report.yml}`, and explicit zero-support / "AS IS" liability notices across `README.md`, `README.de.md`, `README.es.md`, `readme.txt`, `SECURITY.md`, and `llms.txt`.
- Migrated plugin author/catalog/repository metadata to personal open-source distribution (`Arnold Wender`, `https://arnoldwender.com/wordpress-plugins/wm-kanzlei-ai-sanitizer/`, `https://github.com/arnoldwender/wm-wp-kanzlei-ai-sanitizer`), normalized FSF GPL-2.0 `LICENSE` metadata where applicable, and updated `.wordpress-org/` banner branding to `ARNOLD WENDER · OPEN SOURCE`.

## [Unreleased]

## [1.1.3] - 2026-11-19

### Added
- Official `.wordpress-org/` directory visual kit (`icon.svg`, `icon-128x128.png`, `icon-256x256.png`, `banner-772x250.png`, `banner-1544x500.png`) and live Playwright screenshots (`screenshot-1.png` and `screenshot-2.png`) with `== Screenshots ==` in `readme.txt`.
- Visual previews and direct link to `https://arnoldwender.com/wordpress-plugins/wm-kanzlei-ai-sanitizer/` in `README.md`, `README.de.md`, `README.es.md`, and `llms.txt`.

### Changed
- Archived superseded early banners, mockups, and screenshots non-destructively in `versionen/visuals-pre-2026-11-19/` and excluded `versionen/` from distribution packages via `.distignore`.
- Updated release metadata and SBOM (`bom.json`) to `1.1.3`.

---

## [1.1.2] - 2026-11-19

### Changed
- Point `Plugin URI` to `https://arnoldwender.com/wordpress-plugins/wm-kanzlei-ai-sanitizer/` and align release metadata at `v1.1.2`.

## [1.1.1] - 2026-11-18

### Added

- **Steuer-ID Mod 11,10 validation (`NerEngine::steuer_id_checksum_ok`):** validates 11-digit German tax IDs against the official BZSt § 139b AO / ISO/IEC 7064 Mod 11,10 rules (leading non-zero digit, no three consecutive identical digits, exactly one digit repeated two or three times in the first 10 digits, and Mod 11,10 check digit).
- **Non-blocking review warnings (`NerEngine::collect_review_warnings`):** returns `steuer_id_unverified_checksum` when a redacted `STEUER_ID` candidate fails the Mod 11,10 check and `possible_trailing_name_word` when a `PERSON_NAME` entity is immediately followed by whitespace and an unredacted capitalised German word outside `NOT_A_NAME` and not overlapping another entity. Surfaced via `review_warnings` in REST `POST /wm-kanzlei/v1/sanitize` and as an inline `notice-warning` box in the Admin simulator (`AdminDashboard`).
- **Multisite sub-site table initialisation (`wp_initialize_site` & `Schema::activate( bool $network_wide )`):** automatically creates `wm_kanzlei_sessions` and `wm_kanzlei_audit_log` under `switch_to_blog()` / `restore_current_blog()` when a new Multisite sub-site is initialised with the plugin network-activated, and iterates existing sites on network-wide activation.

### Fixed

- **Leading-zero 11-digit phone numbers (`STEUER_ID` pattern):** tightened the `STEUER_ID` pattern from `\d{2}` to `[1-9]\d` so German leading-zero 11-digit phone numbers (e.g. `01761234567`, `03451234567`) classify as `PHONE` rather than `STEUER_ID`.

## [1.1.0] - 2026-11-16

### Added

- **Opt-in uninstallation (`wm_kanzlei_delete_data_on_uninstall`):** `uninstall.php` now preserves plugin options and both tables (`wm_kanzlei_sessions`, `wm_kanzlei_audit_log`) by default and deletes them only when explicitly enabled on the *Einstellungen* tab (`register_setting` registered).
- **Ecosystem bridges (`EcosystemBridge`):** WP 6.5+ Block Bindings source `wm-kanzlei/stats` and GenerateBlocks 2.x Dynamic Tag `{{wm_kanzlei_stat}}` exposing read-only operational counters (`sessions`, `replaced`, `audit_rows`, `active_types`, `chain_status`).
- **Developer extensibility hooks:** `wm_kanzlei_entity_patterns`, `wm_kanzlei_sanitized_result`, `wm_kanzlei_stat_value` filters and `wm_kanzlei_ready` action.
- **Translations & distribution metadata:** full translations across all 28 `.po`/`.mo` locale catalogs, CycloneDX 1.6 `bom.json`, `.wordpress-org/blueprints/blueprint.json`, `.license-allowlist.yml`, and `AGENTS.md` symlinked to `CLAUDE.md`.

### Changed

- **`RequestShield` debug guard:** PHP `error_log` reporting runs only when `WP_DEBUG` is enabled; `wm_sentinel_security_incident` continues to fire unconditionally.
- **Licensing alignment:** `README.md`, `README.de.md`, and `README.es.md` aligned to `GNU General Public License v2 or later` (`GPL-2.0-or-later`) matching the plugin header, `readme.txt`, `composer.json`, and `LICENSE`.


### Added — the catalog freshness gate (2026-09-20)

- `tests/test-pot-freshness.php` and two CI steps on PHP 8.3: the gate extracts the translatable strings from the source and fails if any of them lacks an entry in the `.pot`. A string with no catalog entry cannot be translated by anyone into any language — the translator never sees it, nothing reports an error, and the interface simply stays German.
- **This catalog was already current** — 79 translatable strings, 80 entries, nothing missing and nothing stale — and that is the reason to add the gate rather than a reason to skip it. Fifteen of the fleet's twenty-four plugins had drifted, one of them down to a single entry still shared with the code, and not one of them had a check that could notice. Being correct today is not a mechanism.
- The gate takes its definition of "fresh" from `wp i18n make-pot` rather than a regex of its own, reads the text domain from the plugin header instead of holding a second copy, treats 0 extracted strings as a failure rather than a pass, ignores the plugin-header fields `make-pot` adds, requires wp-cli with no escape hatch, and runs its own self-test before judging the plugin. **This plugin keeps its catalog with `xgettext` (CLAUDE.md rule 6), not with `make-pot`** — that is unchanged: the gate measures the result, whatever tool produced it.
### Family sheets (2026-09-16)
- Re-synced from the hub: the badge variants carry the state tokens on body surfaces, where the command-banner inks measured 1.49:1 to 2.21:1 against the composed background (hub PR #19), and the canonical sheet dropped five classes that belonged to a single plugin (hub PR #21). `tests/test-ui-family.php` re-pins both md5s.

### Fixed (reader pass, 2026-09-15)

- **`/proxy` fabricated a legal opinion.** It wrapped the prompt in a fixed German text ("die geltend gemachten Ansprüche vollumfänglich begründet … unverzüglich Klage einzureichen") and returned `"stgb_203_certified": true`; no provider was called. It now answers 501 `wm_kanzlei_no_provider`.
- **`/certificate` issued forgeable certificates.** Any user with `edit_posts` got a "§ 203 StGB & § 43e BRAO" certificate with `zero_pii_retention: true` for any session id, including ones that never existed, and a hash computable from a literal in the source. It now returns the stored record of a real session (administrators or the session's user) with the chain status and a note that it certifies nothing, or 404.
- **The audit "hash chain" did not chain.** Every row had `previous_hash = sha256('INIT')` and a hash of session id and time. `AuditChain` now seals each row with an HMAC (`wp_salt( 'secure_auth' )`) over the previous seal and the contents, mirrors the tip in an option, takes a lock and verifies (`INTACT`, `EMPTY_CHAIN`, `UNCHAINED_ONLY`, `BROKEN`); `/sanitize` returns nothing when the row cannot be written.
- **Detection bugs, measured with the reader's probe:** BGH/BVerfG/BAG file numbers (`VI ZR 244/20`, `1 BvR 102/22`, `5 AZR 100/23`) never matched; amounts with `€` or `$` never matched (a trailing `\b`), nor `5000 EUR` or `EUR 3.200,00`; `+49 345 …` and `+49 (0)345 …` were missed; names after `Herrn`, `Rechtsanwältin`, `Mandantin`, `dem Beklagten` were missed, `Frau Dr. Schneider` became `Frau Dr` and `Herr Hans-Peter Schmidt` `Herr Hans`, and a later bare surname stayed in clear text; lowercase and hyphenated IBANs and 13-digit numbers were cut into readable fragments by the phone pattern; an IBAN swallowed following capitalised words. IBANs are now checked with mod-97.
- **Invalid UTF-8 disabled detection silently:** one Windows-1252 byte made every `/u` pattern return nothing and the text counted as clean. Detection now refuses such text (400 on REST, error on CLI and in the simulator).
- **Placeholders had 32 bits** and could collide within a text; now 64 bits with a collision check. **`/rehydrate` crashed** (TypeError, HTTP 500) on a malformed mapping; now 400. The prompt `"0"` was refused as empty.
- **Settings were write-only:** nothing read `wm_kanzlei_settings`, and every save reset an `alert_email` the form did not contain. The seven switches now decide what is replaced, and saves keep unknown keys; the provider and retention fields, which configured nothing, are gone.
- **Any Contributor could write made-up rows into the audit log** (demo seeder with a shared nonce, one row naming a client). The seeder is removed; the log and settings need `manage_options`; each form has its own nonce. The admin screen showed the log to `edit_posts` users while the REST route required `manage_options`.
- **Admin simulator used unsalted md5 placeholders** ("14.500 EUR" recoverable by trying amounts); it now uses the vault with a random salt and stores nothing.
- **WP-CLI** used a fixed salt, documented a `--rehydrate` option it never read, printed raw values and reported "PII successfully redacted and vaulted locally" also when nothing was found; now random salt, masked values, a warning for 0.
- **Hub adapter:** health was the literal `HEALTHY` and the self-test said "NER-Test erfolgreich … (Aktenzeichen, IBAN, E-Mail)" whatever it found; the settings link pointed to `page=wm-kanzlei-dashboard`, which does not exist; the SBOM carried "compliance" properties. Health now follows tables, chain and self-test; the link opens the plugin page.
- **Every request created `uploads/wm-kanzlei/vault`** with four protection files; nothing wrote there. RequestShield wrote the client IP to the PHP error log for every flagged value and called it a block while blocking nothing; the log line no longer has the IP and says "not blocked". The unused classes `DirectoryProtector`, `RateLimiter` and `ErrorSanitizer` were removed.
- **Uninstall** deleted three options nothing wrote and left `wm_kanzlei_settings` and the vault directory; it now removes what the plugin writes. `Schema.php` had no direct-access guard.

### Changed (reader pass, 2026-09-15)

- **Admin screen in German**, rewritten from a Spanish screen that showed "100% RGPD COMPLIANT", "CUSTODIA ACTIVA", "ANONIMIZACIÓN EN MEMORIA", "0 Cloud Data Leakage", "5 Typen", a request count capped at 50, emoji, inline colours and a glossary calling reversible placeholders anonymisation. The dashboard widget loads the family sheets on the dashboard.
- **Documentation measured against the code:** README (EN, new DE and ES), `readme.txt`, header description, `docs/ARCHITECTURE.md`, `docs/LEGAL-COMPLIANCE.md` (quotes of § 203 StGB, § 43e BRAO including Abs. 5, DSGVO Art. 4 Nr. 5 and ErwG 26, and what the plugin does not decide), new `DEVELOPERS.md` (replacing `docs/DEVELOPER-GUIDE.md`, which omitted two routes), `CLAUDE.md`, `AGENTS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `llms.txt`, `public/humans.txt` (without "Founder & CEO", Astro, WCAG 2.2 AAA and the phone number). The README badges "§ 203 StGB Compliant" and "§ 43e BRAO Audited" are gone; banner and mockup are no longer shown and excluded from the package.
- **Catalogs:** `.pot` regenerated from the German source; the 28 `.po` merged (earlier Spanish-source translations obsolete) and recompiled.
- **CI** runs `php -l`, the standalone suite (results line required), the family sheet test, the mutation check and PHPUnit with the strict root configuration.

### Design family (hackaton phase 3, 2026-09-14)

- Admin screen on the WM Suite family sheets (`assets/css/wm-admin-tokens.css`, `assets/css/wm-admin-ui.css`), native `.wrap`, family badge, pinned by `tests/test-ui-family.php`.

---

## [1.0.0] — 2026-08-27

- Initial plugin (`6990559`, 2026-08-27): `NerEngine`, `TokenVault`, REST routes, admin dashboard, WP-CLI command; the same day `504bdf4` added `/proxy` and `/certificate`; later the hub adapter, uninstaller, standalone suite and PHPUnit tests, and on 2026-08-29 28 catalogs described as "24 EU language" (`543957f`). What it did and did not do is described in the reader-pass entries above.
