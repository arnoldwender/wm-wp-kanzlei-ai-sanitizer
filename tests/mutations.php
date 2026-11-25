<?php
/**
 * Literal mutations for tests/run-mutations.sh: each entry undoes one correction of the 2026-09-15 reader pass;
 * the standalone suite must report a failure for every one. Search strings must occur exactly once.
 */

return [
	[
		'D7 Aktenzeichen register back to one capital plus lowercase',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\\s+[A-Z][A-Za-z]{0,3}(?:\\s+[A-Z][A-Za-z]{0,3})?\\s+\\d{1,5}', '\\s+[A-Z][a-z]{0,3}(?:\\s+[A-Z][a-z]{0,3})?\\s+\\d{1,5}' ],
		],
	],
	[
		'D7 Roman numeral chamber dropped',
		[
			[ 'includes/Sanitizer/NerEngine.php', '(?:\\d{1,3}|[IVX]{1,5})\\s+[A-Z]', '\\d{1,3}\\s+[A-Z]' ],
		],
	],
	[
		'D1 invalid UTF-8 no longer refused',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'if ( 1 !== preg_match( \'//u\', $text ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'D5 pattern failure ignored',
		[
			[ 'includes/Sanitizer/NerEngine.php', "\t\tif ( false === \$found ) {\n\t\t\t// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a type code and a PCRE error number; the message is fixed.\n\t\t\tthrow new DetectionFailed( \$type, preg_last_error() );\n\t\t}\n", '' ],
		],
	],
	[
		'D4 IBAN uppercase only again',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\'/(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}(?:[ -]?[A-Za-z0-9]){11,30}/\'', '\'/(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}/\'' ],
		],
	],
	[
		'D4 IBAN mod-97 cut removed',
		[
			[ 'includes/Sanitizer/NerEngine.php', "\t\t\t\$value = self::longest_valid_iban( \$candidate );\n", "\t\t\t\$value = null;\n" ],
		],
	],
	[
		'D4 IBAN trailing words kept on invalid checksum',
		[
			[ 'includes/Sanitizer/NerEngine.php', '$value = (string) preg_replace( \'/(?:[ -][A-Za-z]+)+$/\', \'\', $candidate );', '$value = $candidate;' ],
		],
	],
	[
		'D4 IBAN prefix inside a word accepted',
		[
			[ 'includes/Sanitizer/NerEngine.php', '$boundary = $i + 1 === $n || \' \' === $candidate[ $i + 1 ] || \'-\' === $candidate[ $i + 1 ];', '$boundary = true;' ],
		],
	],
	[
		'D4 IBAN word-ending prefix preferred',
		[
			[ 'includes/Sanitizer/NerEngine.php', "\t\t\tif ( count( \$groups ) > 1 && 1 === preg_match( '/^[A-Za-z]+\$/', \$last_group ) ) {\n\t\t\t\t\$word_ending ??= \$prefix;\n\t\t\t\tcontinue;\n\t\t\t}\n", '' ],
		],
	],
	[
		'D4 phone look-behind removed (fragments in digit runs)',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\'/(?<![\\w+])(?:\\+49', '\'/(?:\\+49' ],
		],
	],
	[
		'D8 phone +49 with space missed again',
		[
			[ 'includes/Sanitizer/NerEngine.php', '(?:\\+49\\s?(?:\\(0\\)\\s?)?|0049\\s?|0)[1-9]', '(?:\\+49|0049|0)[1-9]' ],
		],
	],
	[
		'D2 name triggers without inflections',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'private const NAME_TRIGGERS = \'Herrn?|Frau|Rechtsanwältin|Rechtsanwalt|RAin|RA|Mandantin|Mandanten|Mandant|Zeugin|Zeugen|Zeuge|Beklagten|Beklagter|Beklagte|Klägerin|Klägers|Kläger|Patientin|Patienten|Patient|Dr\\.|Prof\\.\';', 'private const NAME_TRIGGERS = \'Herr|Frau|Dr\\.|Prof\\.|Rechtsanwalt|RA|Mandant|Zeuge|Beklagte(?:r)?|Kläger(?:in)?\';' ],
		],
	],
	[
		'D2 academic titles after the trigger not skipped',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\\s+(?:(?:Dr\\.|Prof\\.)\\s*)*(?:(?:von', '\\s+(?:(?:von' ],
		],
	],
	[
		'D2 role nouns taken as names',
		[
			[ 'includes/Sanitizer/NerEngine.php', '(?!(?:\' . self::NOT_A_NAME . \')(?![\\p{L}]))\' . $name_word . \'(?:\\s+', '\' . $name_word . \'(?:\\s+' ],
		],
	],
	[
		'D2 repeated surnames not replaced',
		[
			[ 'includes/Sanitizer/NerEngine.php', "\t\t\t\$entities = self::resolve_overlaps( array_merge( \$entities, \$this->repeated_surnames( \$entities, \$text ) ) );\n", '' ],
		],
	],
	[
		'D3 amount trailing \\b after the currency again',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\\s?(?:EUR\\b|Euro\\b|USD\\b|€|\\$))/u\'', '\\s?(?:EUR|Euro|USD|€|\\$)\\b)/u\'' ],
		],
	],
	[
		'D3 amount currency prefix dropped',
		[
			[ 'includes/Sanitizer/NerEngine.php', '\'/(?:(?:EUR|USD|€|\\$)\\s?\' . $number . \'(?![\\d.,]*\\d))|', '\'/' ],
		],
	],
	[
		'D15 placeholders back to 8 hex',
		[
			[ 'includes/Sanitizer/TokenVault.php', "\t\t\t\$length = 16;\n", "\t\t\t\$length = 8;\n" ],
		],
	],
	[
		'D14 rehydrate without type checks (TypeError)',
		[
			[ 'includes/Sanitizer/TokenVault.php', 'if ( is_string( $placeholder ) && 1 === preg_match( self::PLACEHOLDER_PATTERN, $placeholder ) && is_string( $value ) ) {', 'if ( true ) {' ],
		],
	],
	[
		'D14 mapping validation accepts anything',
		[
			[ 'includes/Sanitizer/TokenVault.php', 'if ( ! is_string( $placeholder ) || 1 !== preg_match( self::PLACEHOLDER_PATTERN, $placeholder ) || ! is_string( $value ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'D8 chain seal not bound to the previous seal',
		[
			[ 'includes/Audit/AuditChain.php', 'return hash_hmac( \'sha256\', $previous . \'|\' . $record_hash, wp_salt( \'secure_auth\' ) );', 'return hash_hmac( \'sha256\', $record_hash, wp_salt( \'secure_auth\' ) );' ],
		],
	],
	[
		'D8 appended rows point at INIT again',
		[
			[ 'includes/Audit/AuditChain.php', "\t\t\t\$previous = self::chain_head();\n", "\t\t\t\$previous = hash( 'sha256', 'INIT' );\n" ],
		],
	],
	[
		'D8 lock result ignored',
		[
			[ 'includes/Audit/AuditChain.php', 'if ( \'1\' !== (string) $locked ) {', 'if ( false ) {' ],
		],
	],
	[
		'D8 tip moves after a refused insert',
		[
			[ 'includes/Audit/AuditChain.php', "\t\t\tif ( false === \$inserted ) {\n\t\t\t\treturn [ 'ok' => false, 'error' => 'the audit row was refused by the database' ];\n\t\t\t}\n", '' ],
		],
	],
	[
		'D8 removed newest rows not caught',
		[
			[ 'includes/Audit/AuditChain.php', "\t\tif ( '' !== \$stored_tip && ! hash_equals( \$stored_tip, \$expected_prev ) ) {", "\t\tif ( false ) {" ],
		],
	],
	[
		'D8 unchained-only reported as INTACT',
		[
			[ 'includes/Audit/AuditChain.php', "\t\tif ( 0 === \$result['checked'] ) {", "\t\tif ( false ) {" ],
		],
	],
	[
		'D8 missing table read as empty',
		[
			[ 'includes/Audit/AuditChain.php', "\t\tif ( ! self::table_present() ) {\n\t\t\treturn [ 'status' => 'BROKEN', 'error' => 'the audit table is missing' ] + \$result;", "\t\tif ( ! self::table_present() ) {\n\t\t\treturn [ 'status' => 'EMPTY_CHAIN' ] + \$result;" ],
		],
	],
	[
		'D6 /proxy answers 200 again',
		[
			[ 'includes/API/RestController.php', '[ \'status\' => 501 ]', '[ \'status\' => 200 ]' ],
		],
	],
	[
		'D7 /certificate for unknown sessions again',
		[
			[ 'includes/API/RestController.php', "\t\tif ( ! \$session ) {\n\t\t\treturn new WP_Error( 'wm_kanzlei_unknown_session', 'No such session.', [ 'status' => 404 ] );\n\t\t}\n", '' ],
		],
	],
	[
		'D7 /certificate readable by any editor',
		[
			[ 'includes/API/RestController.php', 'if ( ! current_user_can( \'manage_options\' ) && (int) $session[\'operator_id\'] !== get_current_user_id() ) {', 'if ( false ) {' ],
		],
	],
	[
		'D24 the prompt "0" refused again',
		[
			[ 'includes/API/RestController.php', 'if ( ! is_string( $prompt ) || \'\' === $prompt ) {', 'if ( empty( $prompt ) ) {' ],
		],
	],
	[
		'D5 invalid UTF-8 answered with a result',
		[
			[ 'includes/API/RestController.php', "\t\t} catch ( \\InvalidArgumentException \$e ) {\n\t\t\treturn new WP_Error( 'wm_kanzlei_invalid_encoding', \$e->getMessage(), [ 'status' => 400 ] );", "\t\t} catch ( \\InvalidArgumentException \$e ) {\n\t\t\t\$entities = [];" ],
		],
	],
	[
		'D8 text returned although the audit row failed',
		[
			[ 'includes/API/RestController.php', "\t\tif ( ! \$audit['ok'] ) {", "\t\tif ( false ) {" ],
		],
	],
	[
		'D8 orphan session row kept',
		[
			[ 'includes/API/RestController.php', "\t\t\t\$wpdb->delete( \$sessions, [ 'session_id' => \$session_id ], [ '%s' ] );\n", '' ],
		],
	],
	[
		'D14 malformed mapping reaches the vault',
		[
			[ 'includes/API/RestController.php', "\t\tif ( ! TokenVault::is_valid_mapping( \$mapping ) ) {", "\t\tif ( ! is_array( \$mapping ) ) {" ],
		],
	],
	[
		'D11 settings ignored by /sanitize',
		[
			[ 'includes/API/RestController.php', "\t\t\$types = Settings::enabled_types();\n\t\ttry {\n\t\t\t\$entities = \$this->ner_engine->detect_entities( \$prompt, \$types );", "\t\t\$types = NerEngine::TYPES;\n\t\ttry {\n\t\t\t\$entities = \$this->ner_engine->detect_entities( \$prompt, \$types );" ],
		],
	],
	[
		'D11 save overwrites keys the form lacks',
		[
			[ 'includes/Core/Settings.php', "\t\t\$stored = get_option( self::OPTION, [] );\n\t\t\$stored = is_array( \$stored ) ? \$stored : [];\n\t\tforeach ( array_keys( self::SWITCHES ) as \$key ) {\n\t\t\t\$stored[ \$key ] = ! empty( \$posted[ \$key ] );", "\t\t\$stored = [ 'alert_email' => '' ];\n\t\tforeach ( array_keys( self::SWITCHES ) as \$key ) {\n\t\t\t\$stored[ \$key ] = ! empty( \$posted[ \$key ] );" ],
		],
	],
	[
		'D11 missing switch means off',
		[
			[ 'includes/Core/Settings.php', '$out[ $key ] = array_key_exists( $key, $stored ) ? (bool) $stored[ $key ] : true;', '$out[ $key ] = array_key_exists( $key, $stored ) ? (bool) $stored[ $key ] : false;' ],
		],
	],
	[
		'D17 CLI fixed salt again',
		[
			[ 'includes/CLI/KanzleiCommand.php', '$tokenized = Plugin::instance()->get_token_vault()->tokenize( $text, $entities, bin2hex( random_bytes( 16 ) ) );', '$tokenized = Plugin::instance()->get_token_vault()->tokenize( $text, $entities, \'cli-salt-2026\' );' ],
		],
	],
	[
		'D17 CLI prints raw values again',
		[
			[ 'includes/CLI/KanzleiCommand.php', '$lines[] = sprintf( \'  - [%s] %s\', $e[\'type\'], self::mask( (string) $e[\'value\'] ) );', '$lines[] = sprintf( \'  - [%s] %s\', $e[\'type\'], (string) $e[\'value\'] );' ],
		],
	],
	[
		'D19 health literal HEALTHY again',
		[
			[ 'includes/Adapters/Kanzlei_Spoke_Adapter.php', 'if ( ! $this->tables_present() || \'BROKEN\' === AuditChain::verify()[\'status\'] || ! $this->self_test()[\'success\'] ) {', 'if ( false ) {' ],
		],
	],
	[
		'D18 hub settings link to a missing page',
		[
			[ 'includes/Adapters/Kanzlei_Spoke_Adapter.php', 'return admin_url( \'admin.php?page=wm-kanzlei-sanitizer&tab=settings\' );', 'return admin_url( \'admin.php?page=wm-kanzlei-dashboard\' );' ],
		],
	],
	[
		'D19 self-test message says passed regardless',
		[
			[ 'includes/Adapters/Kanzlei_Spoke_Adapter.php', "\t\t\t'message' => [] === \$missing\n", "\t\t\t'message' => true\n" ],
		],
	],
	[
		'D9 editors can save settings',
		[
			[ 'includes/Admin/AdminDashboard.php', "\t\tif ( ! current_user_can( 'manage_options' ) ) {\n\t\t\twp_die(", "\t\tif ( false ) {\n\t\t\twp_die(" ],
		],
	],
	[
		'D10 log tab shown to editors',
		[
			[ 'includes/Admin/AdminDashboard.php', '\'log\'       => [ \'label\' => __( \'Protokoll\', \'wm-kanzlei-ai-sanitizer\' ), \'cap\' => \'manage_options\',', '\'log\'       => [ \'label\' => __( \'Protokoll\', \'wm-kanzlei-ai-sanitizer\' ), \'cap\' => \'edit_posts\',' ],
		],
	],
	[
		'D16 simulator back to unsalted md5',
		[
			[ 'includes/Admin/AdminDashboard.php', '\'tokenized\' => $this->token_vault->tokenize( $state[\'text\'], $entities, bin2hex( random_bytes( 16 ) ) ),', '\'tokenized\' => $this->token_vault->tokenize( $state[\'text\'], $entities, \'\' ),' ],
		],
	],
	[
		'D23 compliance badge back on the admin screen',
		[
			[ 'includes/Admin/AdminDashboard.php', '<span class="wm-badge wm-badge-ghost"><?php esc_html_e( \'KEINE EXTERNEN ANFRAGEN\', \'wm-kanzlei-ai-sanitizer\' ); ?></span>', '<span class="wm-badge wm-badge-green"><?php esc_html_e( \'100% RGPD COMPLIANT\', \'wm-kanzlei-ai-sanitizer\' ); ?></span>' ],
		],
	],
	[
		'D9 settings form accepts any nonce',
		[
			[ 'includes/Admin/AdminDashboard.php', "\t\t\tcheck_admin_referer( 'wm_kanzlei_save_settings', 'wm_kanzlei_nonce' );\n", '' ],
		],
	],
	[
		'D20 client IP back in the error log',
		[
			[ 'includes/Security/RequestShield.php', 'error_log( sprintf( \'[WM-KANZLEI-REQUEST-REPORT] %s in %s "%s" (not blocked)\', $reason, $source, $param ) );', 'error_log( sprintf( \'[WM-SECURITY-BLOCK] %s in %s "%s" from IP %s\', $reason, $source, $param, $ip ) );' ],
		],
	],
	[
		'D13 uninstall leaves the settings',
		[
			[ 'uninstall.php', 'foreach ( [ \'wm_kanzlei_settings\', \'wm_kanzlei_audit_chain_tip\', ', 'foreach ( [ ' ],
		],
	],
	[
		'D13 uninstall leaves the vault directory',
		[
			[ 'uninstall.php', 'if ( is_dir( $wm_kanzlei_vault ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'v1.1 D-UNINSTALL drops data without opt-in',
		[
			[ 'uninstall.php', 'if ( ! filter_var( get_option( \'wm_kanzlei_delete_data_on_uninstall\', false ), FILTER_VALIDATE_BOOLEAN ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'v1.1 settings form ignores uninstall opt-in checkbox',
		[
			[ 'includes/Admin/AdminDashboard.php', 'Settings::save_delete_data_on_uninstall( ! empty( $_POST[ Settings::DELETE_DATA_OPTION ] ) );', 'Settings::save_delete_data_on_uninstall( false );' ],
		],
	],
	[
		'v1.1 RequestShield WP_DEBUG guard dropped',
		[
			[ 'includes/Security/RequestShield.php', 'if ( defined( \'WP_DEBUG\' ) && WP_DEBUG && function_exists( \'error_log\' ) )', 'if ( function_exists( \'error_log\' ) )' ],
		],
	],
	[
		'v1.1 entity_patterns filter bypassed',
		[
			[ 'includes/Sanitizer/NerEngine.php', '$custom_patterns = apply_filters( \'wm_kanzlei_entity_patterns\', [], $text, $types );', '$custom_patterns = [];' ],
		],
	],
	[
		'v1.1 sanitized_result filter bypassed',
		[
			[ 'includes/API/RestController.php', '$filtered = apply_filters( \'wm_kanzlei_sanitized_result\', $payload, $session_id, $found );', '$filtered = null;' ],
		],
	],
	[
		'v1.1 wm_kanzlei_ready action dropped',
		[
			[ 'includes/Core/Plugin.php', 'do_action( \'wm_kanzlei_ready\', $this );', '// ready action omitted' ],
		],
	],
	[
		'v1.1 Block Bindings source name wrong',
		[
			[ 'includes/Integrations/EcosystemBridge.php', "\t\tregister_block_bindings_source(\n\t\t\t'wm-kanzlei/stats',", "\t\tregister_block_bindings_source(\n\t\t\t'wm-kanzlei/wrong'," ],
		],
	],
	[
		'v1.1 GenerateBlocks Dynamic Tag name wrong',
		[
			[ 'includes/Integrations/EcosystemBridge.php', '\'tag\'         => self::GB_DYNAMIC_TAG,', '\'tag\'         => \'wrong_tag\',' ],
		],
	],
	[
		'R2-B7 STEUER_ID pattern allows leading zero',
		[
			[ 'includes/Sanitizer/NerEngine.php', '(?<![\\w\\/.,-])[1-9]\\d\\s?\\d{3}', '(?<![\\w\\/.,-])\\d{2}\\s?\\d{3}' ],
		],
	],
	[
		'R2-B7 steuer_id_checksum_ok skips Mod 11,10 check',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'return $check === (int) $compact[10];', 'return true;' ],
		],
	],
	[
		'R2-B7 steuer_id_checksum_ok ignores single-repeated-digit rule',
		[
			[ 'includes/Sanitizer/NerEngine.php', "\t\tif ( 1 !== \$repeated_digits ) {\n\t\t\treturn false;\n\t\t}\n", '' ],
		],
	],
	[
		'R2-B7 steuer_id_checksum_ok allows three consecutive identical digits',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'if ( 1 === preg_match( \'/(\\d)\\1\\1/\', $body ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'R2-B7 collect_review_warnings drops steuer_id_unverified_checksum',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'if ( \'STEUER_ID\' === $type && \'\' !== $value && ! self::steuer_id_checksum_ok( $value ) ) {', 'if ( false ) {' ],
		],
	],
	[
		'R2-B7 collect_review_warnings drops possible_trailing_name_word',
		[
			[ 'includes/Sanitizer/NerEngine.php', 'if ( \'PERSON_NAME\' !== $type ) {', 'if ( true ) {' ],
		],
	],
	[
		'R2-B7 REST /sanitize omits review_warnings',
		[
			[ 'includes/API/RestController.php', '\'review_warnings\' => $warnings,', '// review_warnings omitted' ],
		],
	],
	[
		'R2-B7 simulator omits notice-warning box',
		[
			[ 'includes/Admin/AdminDashboard.php', '<?php if ( ! empty( $sim[\'result\'][\'warnings\'] ) ) : ?>', '<?php if ( false ) : ?>' ],
		],
	],
	[
		'R2-B8 wp_initialize_site hook omitted',
		[
			[ 'wm-kanzlei-ai-sanitizer.php', 'add_action( \'wp_initialize_site\',', 'add_action( \'wp_initialize_site_disabled\',' ],
		],
	],
	[
		'R2-B8 wp_initialize_site skips switch_to_blog',
		[
			[ 'wm-kanzlei-ai-sanitizer.php', "\tswitch_to_blog( \$blog_id );\n", "\t// switch_to_blog omitted\n" ],
		],
	],
	[
		'R2-B8 wp_initialize_site ignores network-active check',
		[
			[ 'wm-kanzlei-ai-sanitizer.php', 'if ( ! function_exists( \'is_plugin_active_for_network\' ) || ! is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {', 'if ( false ) {' ],
		],
	],
];
