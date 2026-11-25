<?php
/**
 * Plugin Name:       WM Kanzlei AI Sanitizer
 * Plugin URI:        https://arnoldwender.com/wordpress-plugins/wm-kanzlei-ai-sanitizer/
 * Description:       Replaces court file numbers, IBANs, e-mail addresses, tax IDs, phone numbers, names after a title and amounts in a text with placeholders and puts them back into the answer; REST routes, WP-CLI, an admin simulator and an HMAC-chained log. Sends nothing to AI providers.
 * Version:           1.2.2
 * Requires at least: 6.4
 * Tested up to:      7.1
 * Requires PHP:      8.2
 * Author:            Arnold Wender
 * Author URI:        https://arnoldwender.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wm-kanzlei-ai-sanitizer
 * Domain Path:       /languages
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WM_KANZLEI_VERSION' ) ) {
	define( 'WM_KANZLEI_VERSION', '1.2.2' );
}
if ( ! defined( 'WM_KANZLEI_FILE' ) ) {
	define( 'WM_KANZLEI_FILE', __FILE__ );
}
if ( ! defined( 'WM_KANZLEI_PATH' ) ) {
	define( 'WM_KANZLEI_PATH', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'WM_KANZLEI_URL' ) ) {
	define( 'WM_KANZLEI_URL', plugin_dir_url( __FILE__ ) );
}

// Autoloader
spl_autoload_register( function ( string $class ): void {
	$prefix = 'WMCyber\\Kanzlei\\';
	$base_dir = WM_KANZLEI_PATH . 'includes/';

	$len = strlen( $prefix );
	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative_class = substr( $class, $len );
	$file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	}
} );

// Lifecycle Hooks
register_activation_hook( __FILE__, [ Database\Schema::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ Database\Schema::class, 'deactivate' ] );

// Multisite: initialize tables on newly created sub-sites when network-activated.
add_action( 'wp_initialize_site', function ( object $new_site ): void {
	if ( ! function_exists( 'is_multisite' ) || ! is_multisite() ) {
		return;
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) && defined( 'ABSPATH' ) && is_file( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) || ! is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return;
	}
	$blog_id = isset( $new_site->blog_id ) ? (int) $new_site->blog_id : 0;
	if ( $blog_id <= 0 ) {
		return;
	}
	switch_to_blog( $blog_id );
	try {
		Database\Schema::activate();
	} finally {
		restore_current_blog();
	}
}, 10, 1 );

// Register as Spoke in WM Suite Hub
add_filter( 'wm_register_suite_module', function ( array $modules ): array {
	if ( ! class_exists( 'WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter' ) && file_exists( WM_KANZLEI_PATH . 'includes/Adapters/Kanzlei_Spoke_Adapter.php' ) ) {
		require_once WM_KANZLEI_PATH . 'includes/Adapters/Kanzlei_Spoke_Adapter.php';
	}
	if ( class_exists( 'WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter' ) ) {
		$modules[] = new Adapters\Kanzlei_Spoke_Adapter();
	}
	return $modules;
} );

add_action( 'plugins_loaded', function (): void {
	Core\Plugin::instance()->boot();
} );

