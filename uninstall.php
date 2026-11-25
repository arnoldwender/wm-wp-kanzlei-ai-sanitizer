<?php
/**
 * WM Suite Kanzlei AI Sanitizer — Uninstaller
 *
 * Preserves plugin options and the two audit/session tables by default. Only when the administrator has explicitly
 * enabled `wm_kanzlei_delete_data_on_uninstall` on the settings screen does uninstall remove `wm_kanzlei_settings`,
 * `wm_kanzlei_audit_chain_tip`, the opt-in flag, both tables, and the legacy `uploads/wm-kanzlei/vault` directory.
 * On multisite only the current site's tables and options are removed.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( ! filter_var( get_option( 'wm_kanzlei_delete_data_on_uninstall', false ), FILTER_VALIDATE_BOOLEAN ) ) {
	return;
}

global $wpdb;

// 1. Options (the last three were never written by any version; deleting them is a no-op kept for old installs).
foreach ( [ 'wm_kanzlei_settings', 'wm_kanzlei_audit_chain_tip', 'wm_kanzlei_delete_data_on_uninstall', 'wm_kanzlei_options', 'wm_kanzlei_ner_settings', 'wm_kanzlei_salt_key', 'wm_kanzlei_db_version' ] as $wm_kanzlei_option ) {
	delete_option( $wm_kanzlei_option );
	delete_site_option( $wm_kanzlei_option );
}

// 2. Tables.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'wm_kanzlei_sessions' ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'wm_kanzlei_audit_log' ) );

// 3. The vault directory of earlier versions: only the four files they wrote, then the empty directories.
$wm_kanzlei_vault = WP_CONTENT_DIR . '/uploads/wm-kanzlei/vault';
if ( is_dir( $wm_kanzlei_vault ) ) {
	foreach ( [ '.htaccess', 'web.config', 'index.php', 'index.html' ] as $wm_kanzlei_file ) {
		if ( is_file( $wm_kanzlei_vault . '/' . $wm_kanzlei_file ) ) {
			wp_delete_file( $wm_kanzlei_vault . '/' . $wm_kanzlei_file );
		}
	}
	// rmdir only succeeds on an empty directory, so anything else someone put there stays.
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	@rmdir( $wm_kanzlei_vault );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	@rmdir( dirname( $wm_kanzlei_vault ) );
}
