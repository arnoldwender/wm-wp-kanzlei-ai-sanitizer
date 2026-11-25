<?php
declare(strict_types=1);

namespace WMCyber\Kanzlei\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Schema {
	public static function activate( bool $network_wide = false ): void {
		if ( $network_wide && function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_sites' ) ) {
			$site_ids = get_sites( [ 'fields' => 'ids', 'number' => 0 ] );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				try {
					self::activate_single_site();
				} finally {
					restore_current_blog();
				}
			}
			return;
		}
		self::activate_single_site();
	}

	private static function activate_single_site(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$table_sessions = $wpdb->prefix . 'wm_kanzlei_sessions';
		$table_audit    = $wpdb->prefix . 'wm_kanzlei_audit_log';

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		// 1. Sanitization Sessions
		$sql_sessions = "CREATE TABLE $table_sessions (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			session_id varchar(64) NOT NULL,
			operator_id bigint(20) unsigned NOT NULL DEFAULT 0,
			entities_redacted int unsigned NOT NULL DEFAULT 0,
			prompt_tokens_est int unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_session_id (session_id),
			KEY idx_operator (operator_id)
		) $charset_collate;";
		dbDelta( $sql_sessions );

		// 2. Audit log: one row per sanitisation, HMAC-chained by AuditChain. The column compliance_standard and
		// its default are from the first version; AuditChain writes 'NONE', the plugin assesses no standard.
		$sql_audit = "CREATE TABLE $table_audit (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			session_id varchar(64) NOT NULL,
			action varchar(64) NOT NULL,
			entity_types_summary varchar(255) NOT NULL,
			compliance_standard varchar(32) NOT NULL DEFAULT 'BRAO_43E_STGB_203',
			previous_hash varchar(64) NOT NULL,
			current_hash varchar(64) NOT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY idx_session (session_id)
		) $charset_collate;";
		dbDelta( $sql_audit );
		update_option( 'wm_kanzlei_db_version', 2, false );
	}

	/**
	 * Bring tables forward on already-active installs where activation does not re-run.
	 */
	public static function maybe_upgrade(): void {
		if ( 2 <= (int) get_option( 'wm_kanzlei_db_version', 0 ) ) {
			return;
		}
		self::activate_single_site();
	}

	public static function deactivate(): void {}
}
