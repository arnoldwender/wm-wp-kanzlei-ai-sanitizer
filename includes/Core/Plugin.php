<?php
/**
 * Boot: text domain, request inspection, REST routes, admin screen, WP-CLI.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\Kanzlei\Sanitizer\NerEngine;
use WMCyber\Kanzlei\Sanitizer\TokenVault;
use WMCyber\Kanzlei\API\RestController;
use WMCyber\Kanzlei\CLI\KanzleiCommand;
use WMCyber\Kanzlei\Admin\AdminDashboard;
use WMCyber\Kanzlei\Integrations\EcosystemBridge;

final class Plugin {
	private static ?Plugin $instance = null;
	private NerEngine $ner_engine;
	private TokenVault $token_vault;

	private function __construct() {
		$this->ner_engine  = new NerEngine();
		$this->token_vault = new TokenVault();
	}

	public static function instance(): Plugin {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot(): void {
		\WMCyber\Kanzlei\Database\Schema::maybe_upgrade();

		add_action( 'init', function (): void {
			load_plugin_textdomain(
				'wm-kanzlei-ai-sanitizer',
				false,
				dirname( plugin_basename( WM_KANZLEI_FILE ) ) . '/languages'
			);
		} );

		// Until 2026-09-15 every request also created uploads/wm-kanzlei/vault with four protection files
		// (DirectoryProtector::protect()); nothing ever wrote to that directory. uninstall.php removes it.
		// RequestShield reports suspicious stream wrappers; it does not block the request.
		\WMCyber\Kanzlei\Security\RequestShield::inspect_globals();

		( new RestController( $this->ner_engine, $this->token_vault ) )->register_routes();
		( new EcosystemBridge() )->init();

		if ( is_admin() ) {
			( new AdminDashboard( $this->ner_engine, $this->token_vault ) )->init();
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			KanzleiCommand::register();
		}

		if ( function_exists( 'do_action' ) ) {
			/**
			 * Fires once WM Kanzlei AI Sanitizer has booted its routes, integrations and hooks.
			 *
			 * @param Plugin $plugin Singleton plugin instance.
			 */
			do_action( 'wm_kanzlei_ready', $this );
		}
	}

	public function get_ner_engine(): NerEngine {
		return $this->ner_engine;
	}

	public function get_token_vault(): TokenVault {
		return $this->token_vault;
	}
}
