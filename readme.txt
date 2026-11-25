=== WM Kanzlei AI Sanitizer ===
Contributors: arnoldwender
Tags: legal, placeholders, pseudonymisation, rest-api, wp-cli
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.2.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Replaces court file numbers, IBANs and other values in a text with placeholders and puts them back. Sends nothing.

== Description ==

* **Detection:** regular expressions for seven types — court file numbers, IBANs (checked with mod-97), e-mail addresses, 11-digit tax IDs, German phone numbers, names after a title or role, amounts. Not detected: names without a title, addresses, dates of birth, tax and social security numbers, ID card numbers, health data and more (see README).
* **REST:** `wm-kanzlei/v1/sanitize` replaces the values and returns the text and the mapping; `/rehydrate` puts them back; `/audit-log` lists the log with a chain check; `/certificate` returns the record of one session; `/proxy` answers 501 because no AI provider is connected.
* **Log:** one row per sanitisation, HMAC-chained with the site salts; tamper-evident, re-sealable by anyone holding `wp-config.php`.
* **Admin:** German screen with overview, simulator, settings (which types are replaced plus opt-in uninstallation) and log; dashboard widget.
* **WP-CLI:** `wp kanzlei sanitize "<text>"`.
* **Extensibility:** WP 6.5+ Block Bindings (`wm-kanzlei/stats`), GenerateBlocks 2.x Dynamic Tag (`{{wm_kanzlei_stat}}`), developer filters (`wm_kanzlei_entity_patterns`, `wm_kanzlei_sanitized_result`, `wm_kanzlei_stat_value`) and action (`wm_kanzlei_ready`).

The plugin sends no text to any AI provider, stores neither the text nor the mapping, and does not decide whether a text may be given to a service provider (§ 203 StGB, § 43e BRAO, DSGVO).

== Frequently Asked Questions ==

= Is technical or private support provided? =

No. This plugin comes with zero support (`0` support). Private inquiries sent via email, `arnoldwender.com`, or social/chat channels are not answered. Reproducible bugs belong solely on GitHub Issues (`https://github.com/arnoldwender/wm-wp-kanzlei-ai-sanitizer/issues`) with no guarantee of reply or resolution. The software is provided **"AS IS"** at your sole risk with zero warranty or liability (see `SUPPORT.md` in the repository).

== Screenshots ==

1. Overview: call, replaced-value and log-row counts, what the plugin does and what it does not detect
2. WordPress dashboard widget showing local redaction statistics

== Changelog ==


= 1.2.2 =
* Fixed: Screenshot 1 showed the WM Suite menu from before WM Suite Hub 1.2.3, with entries the hub no longer has («Marketplace (Lösungspakete)», «Merkle-Audit-Protokoll», «CRA- & SBOM-Zentrale»). It is retaken with the current menu; the plugin's code is unchanged.

= 1.2.1 =
* Fixed: the simulator's "Prüfhinweise" heading was untranslated in all 28 catalogs, and "%d Wert ersetzt" repeated one plural form in ten languages with three or more forms.
* The bundled family stylesheet is identical to WM Suite Hub 1.2.5 again: it starts the admin header below WordPress's help toggle instead of shortening it. This plugin's own screens register no help tab, so they change only where another plugin adds one.

= 1.2.0 =
* The WM Suite Hub contract now lives in the `ArnoldWender\SuiteHub\Contracts` namespace. The spoke adapter registers only with WM Suite Hub 1.2.0 or later, so update the hub together with this plugin; used on its own, the plugin works as before.
* The `.wordpress-org/` banners show the current version.
* The first screenshot description names what the screen shows (the overview), not a masking workbench and audit log "protecting" values before AI prompts.
* Removed: The archived pre-2026-11-19 marketing visuals in `versionen/`: they claimed features and conformity the plugin does not have. They were never part of the installable package.

= 1.1.4 =
* Removed the agency name, links to unrelated projects and the personal mailbox from code, catalogs and documentation; the admin family badge and the hub menu read "WM Suite". The READMEs say the plugin was built with an agentic workflow (AI coding agents) and should be reviewed like any third-party code.
* Added root `SUPPORT.md`, GitHub Issue templates, explicit zero-support & "AS IS" liability notices in READMEs and `readme.txt`, and normalized canonical GPLv2+ `arnoldwender.com` / `arnoldwender/wm-wp-kanzlei-ai-sanitizer` links.
* Updated `.wordpress-org/` visual banners to personal `ARNOLD WENDER · OPEN SOURCE` branding.

= 1.1.3 =
* Add `.wordpress-org/` vector icons, banners (`772x250`, `1544x500`), live WordPress screenshots (`screenshot-1.png` and `screenshot-2.png`) and `== Screenshots ==` descriptions.
* Update trilingual READMEs and `llms.txt` with live previews and direct plugin catalog link (`https://arnoldwender.com/wordpress-plugins/wm-kanzlei-ai-sanitizer/`).

= 1.1.2 =
* Point Plugin URI to the official plugin page.

= 1.1.1 =
* Tightened `STEUER_ID` regex to require a non-zero leading digit (`[1-9]\d`) so 11-digit German phone numbers (`0176...`, `0345...`) classify as `PHONE` instead of `STEUER_ID`.
* Added official BZSt § 139b AO / ISO 7064 Mod 11,10 check (`NerEngine::steuer_id_checksum_ok()`) and `collect_review_warnings()` (`steuer_id_unverified_checksum` and `possible_trailing_name_word`), surfaced via REST `/sanitize` (`review_warnings`) and an inline `notice-warning` box in the admin simulator.
* Hooked `wp_initialize_site` and network-wide `Schema::activate()` so Multisite sub-sites initialise plugin tables under `switch_to_blog()` / `restore_current_blog()`.

= 1.1.0 =
* Preserved options and both tables (`wm_kanzlei_sessions`, `wm_kanzlei_audit_log`) on uninstall by default unless `wm_kanzlei_delete_data_on_uninstall` is explicitly enabled on the settings screen.
* Added WP 6.5+ Block Bindings source (`wm-kanzlei/stats`), GenerateBlocks 2.x Dynamic Tag (`{{wm_kanzlei_stat}}`), developer filters (`wm_kanzlei_entity_patterns`, `wm_kanzlei_sanitized_result`, `wm_kanzlei_stat_value`) and action (`wm_kanzlei_ready`).
* Guarded `RequestShield` PHP error-log reporting behind `WP_DEBUG` while keeping `wm_sentinel_security_incident` active.
* Completed translations across all 28 `.po`/`.mo` catalogs, aligned GPLv2-or-later licensing across docs, and added CycloneDX 1.6 `bom.json` and WordPress Playground blueprint.
* Removed a fixed legal opinion returned by /proxy and forgeable certificates returned by /certificate; /proxy answers 501, /certificate returns the stored record or 404.
* The audit log is now an HMAC chain with a recorded tip and a verifier; rows from before the chain count as unchained.
* Detection fixed for BGH/BVerfG file numbers, amounts with € and $, +49 phone numbers with spaces, names after Herrn/Rechtsanwältin/Mandantin and after academic titles, repeated surnames, lowercase and hyphenated IBANs; invalid UTF-8 is refused.
* Settings take effect; the demo button that wrote made-up rows into the log is gone; the log needs manage_options.
* German admin screen without conformity claims; simulator with salted placeholders; CLI with random salt and masked output.
* Admin screen on the WM Suite family sheets (shared tokens and components, visible focus rings, native wrap, family badge).

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.2.2 =
Screenshot 1 retaken with the current WM Suite menu. No code, data or settings change.

= 1.2.1 =
The family sheet of WM Suite Hub 1.2.5 and translation fixes in the simulator. No data or settings change.

= 1.2.0 =
Hub users: update WM Suite Hub to 1.2.0 together with this plugin. The hub contract moved to a new PHP namespace; next to an older hub the plugin keeps working, but it is not listed in the cockpit and its admin page has no menu entry until the hub is updated.
