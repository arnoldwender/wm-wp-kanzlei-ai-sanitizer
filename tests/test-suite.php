<?php
/**
 * Standalone test suite for wm-kanzlei-ai-sanitizer (no WordPress, no MySQL).
 *
 * The mock $wpdb understands exactly the statements the plugin sends and throws on anything else, so a changed
 * query fails loudly instead of returning a friendly default. Groups:
 *  1 detection (measured leak cases), 2 IBAN check digits, 3 placeholders and rehydration, 4 REST routes,
 *  5 audit chain, 6 settings, 7 WP-CLI, 8 hub adapter, 9 admin screen, 10 boot and request report,
 *  11 uninstall, 12 claims in docs and code.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace ArnoldWender\SuiteHub\Contracts {
	interface WM_Plugin_Module_Interface {
		public function get_module_slug(): string;
		public function get_name(): string;
		public function get_version(): string;
		public function get_description(): string;
		public function get_health_status(): string;
		public function get_sbom_data(): array;
		public function get_dependencies(): array;
		public function get_settings_url(): ?string;
		public function get_telemetry_metrics(): array;
		public function execute_action( string $action, array $params = [] ): array;
	}
}

namespace {
	error_reporting( E_ALL );

	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
	define( 'WM_KANZLEI_VERSION', '1.2.2' );
	define( 'WM_KANZLEI_FILE', dirname( __DIR__ ) . '/wm-kanzlei-ai-sanitizer.php' );
	define( 'WM_KANZLEI_PATH', dirname( __DIR__ ) . '/' );
	define( 'WM_KANZLEI_URL', 'https://example.test/wp-content/plugins/wm-kanzlei-ai-sanitizer/' );
	define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/wm-kanzlei-suite-' . getmypid() );

	// --- Mock $wpdb -------------------------------------------------------------------------------------------
	final class Kanzlei_Mock_WPDB {
		public string $prefix = 'wp_';
		public int $insert_id = 0;
		/** @var array<string, array<int, array<string, mixed>>> */
		public array $tables = [ 'wp_wm_kanzlei_sessions' => [], 'wp_wm_kanzlei_audit_log' => [] ];
		public array $auto = [];
		public string $lock_answer = '1';
		public bool $refuse_insert = false;
		public array $queries = [];
		public array $locks = [];

		public function get_charset_collate(): string { return ''; }
		public function esc_like( string $text ): string { return addcslashes( $text, '_%\\' ); }

		public function prepare( string $query, ...$args ): string {
			if ( 1 === count( $args ) && is_array( $args[0] ) ) {
				$args = $args[0];
			}
			$i = 0;
			return (string) preg_replace_callback( '/%[isd]/', static function ( array $m ) use ( &$i, $args ): string {
				$v = $args[ $i++ ] ?? null;
				return match ( $m[0] ) {
					'%i' => '`' . $v . '`',
					'%d' => (string) (int) $v,
					default => "'" . addslashes( (string) $v ) . "'",
				};
			}, $query );
		}

		public function insert( string $table, array $data, $format = null ) {
			$this->queries[] = "INSERT {$table}";
			if ( $this->refuse_insert || ! array_key_exists( $table, $this->tables ) ) {
				return false;
			}
			$this->auto[ $table ] = ( $this->auto[ $table ] ?? 0 ) + 1;
			$this->insert_id      = $this->auto[ $table ];
			$this->tables[ $table ][ $this->insert_id ] = [ 'id' => $this->insert_id ] + $data;
			return 1;
		}

		public function delete( string $table, array $where, $format = null ) {
			$this->queries[] = "DELETE {$table}";
			$n = 0;
			foreach ( $this->tables[ $table ] ?? [] as $id => $row ) {
				if ( array_intersect_assoc( array_map( 'strval', $where ), array_map( 'strval', $row ) ) === array_map( 'strval', $where ) ) {
					unset( $this->tables[ $table ][ $id ] );
					++$n;
				}
			}
			return $n;
		}

		private function table_of( string $sql ): string {
			if ( ! preg_match( '/FROM `([^`]+)`/', $sql, $m ) ) {
				throw new RuntimeException( "mock wpdb: no table in: {$sql}" );
			}
			return $m[1];
		}

		public function get_var( string $sql ) {
			$this->queries[] = $sql;
			if ( preg_match( "/^SELECT GET_LOCK\( '([^']+)', \d+ \)$/", $sql, $m ) ) {
				if ( '1' === $this->lock_answer ) {
					$this->locks[ $m[1] ] = true;
				}
				return $this->lock_answer;
			}
			if ( preg_match( "/^SELECT RELEASE_LOCK\( '([^']+)' \)$/", $sql, $m ) ) {
				unset( $this->locks[ $m[1] ] );
				return '1';
			}
			if ( preg_match( "/^SHOW TABLES LIKE '(.+)'$/", $sql, $m ) ) {
				// SQL string literal first (addslashes in prepare), then the LIKE escapes of esc_like.
				$name = str_replace( [ '\\_', '\\%', '\\\\' ], [ '_', '%', '\\' ], stripslashes( $m[1] ) );
				return array_key_exists( $name, $this->tables ) ? $name : null;
			}
			if ( preg_match( '/^SELECT COUNT\(\*\) FROM `[^`]+`$/', $sql ) ) {
				return (string) count( $this->rows( $this->table_of( $sql ) ) );
			}
			if ( preg_match( '/^SELECT COALESCE\(SUM\(entities_redacted\), 0\) FROM `[^`]+`$/', $sql ) ) {
				return (string) array_sum( array_column( $this->rows( $this->table_of( $sql ) ), 'entities_redacted' ) );
			}
			if ( preg_match( "/^SELECT current_hash FROM `[^`]+` WHERE previous_hash <> '' ORDER BY id DESC LIMIT 1$/", $sql ) ) {
				$sealed = array_filter( $this->rows( $this->table_of( $sql ) ), static fn( $r ) => '' !== (string) $r['previous_hash'] );
				krsort( $sealed );
				return $sealed ? (string) reset( $sealed )['current_hash'] : null;
			}
			throw new RuntimeException( "mock wpdb: unexpected get_var: {$sql}" );
		}

		private function rows( string $table ): array {
			if ( ! array_key_exists( $table, $this->tables ) ) {
				throw new RuntimeException( "mock wpdb: table {$table} does not exist" );
			}
			ksort( $this->tables[ $table ] );
			return $this->tables[ $table ];
		}

		public function get_results( string $sql, $output = OBJECT ) {
			$this->queries[] = $sql;
			if ( preg_match( '/^SELECT ([a-z_, ]+) FROM `[^`]+` ORDER BY id (ASC|DESC)(?: LIMIT (\d+))?$/', $sql, $m ) ) {
				$cols = array_map( 'trim', explode( ',', $m[1] ) );
				$rows = array_values( $this->rows( $this->table_of( $sql ) ) );
				if ( 'DESC' === $m[2] ) {
					$rows = array_reverse( $rows );
				}
				if ( isset( $m[3] ) ) {
					$rows = array_slice( $rows, 0, (int) $m[3] );
				}
				return array_map( static fn( $r ) => array_intersect_key( $r, array_flip( $cols ) ) + array_fill_keys( $cols, '' ), $rows );
			}
			throw new RuntimeException( "mock wpdb: unexpected get_results: {$sql}" );
		}

		public function get_row( string $sql, $output = OBJECT ) {
			$this->queries[] = $sql;
			if ( preg_match( "/^SELECT ([a-z_, ]+) FROM `[^`]+` WHERE session_id = '([^']*)'(?: ORDER BY id ASC LIMIT 1)?$/", $sql, $m ) ) {
				$cols = array_map( 'trim', explode( ',', $m[1] ) );
				foreach ( $this->rows( $this->table_of( $sql ) ) as $row ) {
					if ( (string) $row['session_id'] === stripslashes( $m[2] ) ) {
						return array_intersect_key( $row, array_flip( $cols ) );
					}
				}
				return null;
			}
			throw new RuntimeException( "mock wpdb: unexpected get_row: {$sql}" );
		}

		public function query( string $sql ) {
			$this->queries[] = $sql;
			if ( preg_match( '/^DROP TABLE IF EXISTS `([^`]+)`$/', $sql, $m ) ) {
				unset( $this->tables[ $m[1] ] );
				return true;
			}
			throw new RuntimeException( "mock wpdb: unexpected query: {$sql}" );
		}
	}
	define( 'OBJECT', 'OBJECT' );
	define( 'ARRAY_A', 'ARRAY_A' );
	$GLOBALS['wpdb'] = new Kanzlei_Mock_WPDB();

	function k9z_reset(): void {
		$GLOBALS['wpdb']                     = new Kanzlei_Mock_WPDB();
		$GLOBALS['mock_options']             = [];
		$GLOBALS['mock_caps']                = [ 'edit_posts' => true, 'manage_options' => true ];
		$GLOBALS['mock_user']                = 7;
		$GLOBALS['mock_filters']             = [];
		$GLOBALS['mock_dispatched_actions']  = [];
		$GLOBALS['mock_registered_settings'] = [];
		$GLOBALS['mock_block_bindings']      = [];
		$GLOBALS['mock_multisite']           = false;
		$GLOBALS['mock_network_active']      = false;
		$GLOBALS['mock_blog_stack']          = [];
		$GLOBALS['mock_site_ids']            = [ 1 ];
		GenerateBlocks_Register_Dynamic_Tag::$registered = [];
	}

	// --- WordPress function stubs ---------------------------------------------------------------------------------
	$GLOBALS['mock_actions']             = [];
	$GLOBALS['mock_filters']             = [];
	$GLOBALS['mock_dispatched_actions']  = [];
	$GLOBALS['mock_registered_settings'] = [];
	$GLOBALS['mock_block_bindings']      = [];
	$GLOBALS['mock_routes']              = [];
	function add_action( string $tag, $cb, int $priority = 10, int $args = 1 ): void { $GLOBALS['mock_actions'][ $tag ][] = $cb; }
	function do_action( string $tag, ...$args ): void { $GLOBALS['mock_dispatched_actions'][ $tag ][] = $args; }
	function add_filter( string $tag, $cb, int $priority = 10, int $args = 1 ): void { $GLOBALS['mock_filters'][ $tag ][ $priority ][] = [ 'cb' => $cb, 'args' => $args ]; }
	function apply_filters( string $tag, $value, ...$args ) {
		if ( empty( $GLOBALS['mock_filters'][ $tag ] ) ) {
			return $value;
		}
		ksort( $GLOBALS['mock_filters'][ $tag ] );
		$all = array_merge( [ $value ], $args );
		foreach ( $GLOBALS['mock_filters'][ $tag ] as $list ) {
			foreach ( $list as $entry ) {
				$all[0] = ( $entry['cb'] )( ...array_slice( $all, 0, max( 1, (int) $entry['args'] ) ) );
			}
		}
		return $all[0];
	}
	function register_setting( string $group, string $name, $args = [] ): void { $GLOBALS['mock_registered_settings'][ $name ] = [ 'group' => $group, 'args' => $args ]; }
	function register_block_bindings_source( string $name, array $args ): bool { $GLOBALS['mock_block_bindings'][ $name ] = $args; return true; }
	function is_admin(): bool { return false; }
	function plugin_basename( string $file ): string { return basename( dirname( $file ) ) . '/' . basename( $file ); }
	function plugin_dir_path( string $file ): string { return dirname( $file ) . '/'; }
	function plugin_dir_url( string $file ): string { return 'https://example.test/wp-content/plugins/' . basename( dirname( $file ) ) . '/'; }
	function register_activation_hook( string $file, $cb ): void {}
	function register_deactivation_hook( string $file, $cb ): void {}
	function is_multisite(): bool { return ! empty( $GLOBALS['mock_multisite'] ); }
	function is_plugin_active_for_network( string $plugin ): bool { return ! empty( $GLOBALS['mock_network_active'] ); }
	function switch_to_blog( int $blog_id ): bool {
		$GLOBALS['mock_blog_stack'][] = $GLOBALS['wpdb']->prefix;
		$GLOBALS['wpdb']->prefix      = $blog_id > 1 ? 'wp_' . $blog_id . '_' : 'wp_';
		return true;
	}
	function restore_current_blog(): bool {
		$prev = array_pop( $GLOBALS['mock_blog_stack'] );
		if ( is_string( $prev ) ) {
			$GLOBALS['wpdb']->prefix = $prev;
		}
		return true;
	}
	function get_sites( array $args = [] ): array { return $GLOBALS['mock_site_ids']; }
	function dbDelta( $queries ): array {
		$list = is_array( $queries ) ? $queries : [ (string) $queries ];
		foreach ( $list as $sql ) {
			if ( preg_match( '/CREATE TABLE\s+([A-Za-z0-9_]+)/i', (string) $sql, $m ) ) {
				$GLOBALS['wpdb']->tables[ $m[1] ] ??= [];
			}
		}
		return [];
	}
	function load_plugin_textdomain( ...$a ): bool { return true; }
	class GenerateBlocks_Register_Dynamic_Tag {
		/** @var list<array<string, mixed>> */
		public static array $registered = [];
		public function __construct( array $args ) { self::$registered[] = $args; }
	}
	function register_rest_route( string $ns, string $route, array $args ): bool { $GLOBALS['mock_routes'][ $ns . $route ] = $args; return true; }
	function get_option( string $name, $default = false ) { return array_key_exists( $name, $GLOBALS['mock_options'] ) ? $GLOBALS['mock_options'][ $name ] : $default; }
	function update_option( string $name, $value, $autoload = null ): bool { $GLOBALS['mock_options'][ $name ] = $value; return true; }
	function delete_option( string $name ): bool { unset( $GLOBALS['mock_options'][ $name ] ); return true; }
	function delete_site_option( string $name ): bool { return true; }
	function wp_salt( string $scheme = 'auth' ): string { return 'suite-salt-' . $scheme . ( $GLOBALS['mock_salt_suffix'] ?? '' ); }
	function current_time( string $type, $gmt = 0 ) { return gmdate( 'Y-m-d H:i:s' ); }
	function get_current_user_id(): int { return (int) $GLOBALS['mock_user']; }
	function current_user_can( string $cap ): bool { return ! empty( $GLOBALS['mock_caps'][ $cap ] ); }
	function admin_url( string $path = '' ): string { return 'https://example.test/wp-admin/' . ltrim( $path, '/' ); }
	function esc_html( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
	function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
	function esc_url( $t ) { return (string) $t; }
	function esc_textarea( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
	function __( $t, $d = '' ) { return $t; }
	function _n( $s, $p, $n, $d = '' ) { return 1 === $n ? $s : $p; }
	function esc_html__( $t, $d = '' ) { return esc_html( $t ); }
	function esc_html_e( $t, $d = '' ): void { echo esc_html( $t ); }
	function esc_attr_e( $t, $d = '' ): void { echo esc_attr( $t ); }
	function number_format_i18n( $n ) { return number_format( (float) $n, 0, ',', '.' ); }
	function wp_nonce_field( $action, $name ): void { echo '<input type="hidden" name="' . $name . '" value="nonce-' . $action . '">'; }
	function wp_verify_nonce( $nonce, $action ) { return 'nonce-' . $action === $nonce ? 1 : false; }
	function check_admin_referer( $action, $name ) { if ( ( $_POST[ $name ] ?? '' ) !== 'nonce-' . $action ) { throw new RuntimeException( 'bad nonce' ); } return 1; }
	function sanitize_text_field( $t ) { return trim( strip_tags( (string) $t ) ); }
	function sanitize_key( $t ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $t ) ); }
	function wp_unslash( $v ) { return is_string( $v ) ? stripslashes( $v ) : $v; }
	function checked( $v, $cur = true, $echo = true ) { $r = (bool) $v === (bool) $cur ? ' checked="checked"' : ''; if ( $echo ) { echo $r; } return $r; }
	function wp_add_dashboard_widget( ...$a ): void {}
	function add_menu_page( ...$a ): string { return ''; }
	function wp_enqueue_style( ...$a ): void { $GLOBALS['mock_styles'][] = $a[0]; }
	final class K9z_Redirect extends RuntimeException {}
	function wp_safe_redirect( string $url ) { throw new K9z_Redirect( $url ); }
	function wp_die( $msg = '', $code = 0 ) { throw new RuntimeException( 'wp_die: ' . $msg ); }
	function wp_delete_file( string $file ): void { @unlink( $file ); }
	function is_wp_error( $v ): bool { return $v instanceof WP_Error; }

	class WP_Error {
		public function __construct( public string $code = '', public string $message = '', public $data = null ) {}
		public function get_error_code() { return $this->code; }
		public function get_error_message() { return $this->message; }
		public function get_error_data() { return $this->data; }
	}
	class WP_REST_Response {
		public function __construct( public $data = null, public int $status = 200 ) {}
		public function get_data() { return $this->data; }
	}
	class WP_REST_Request {
		public function __construct( private array $params = [] ) {}
		public function get_param( string $key ) { return $this->params[ $key ] ?? null; }
		public function get_json_params() { return $this->params; }
	}
	class WP_CLI_Command {}
	class WP_CLI {
		public static function add_command( ...$a ): void {}
		public static function line( $l ): void {}
		public static function success( $l ): void {}
		public static function warning( $l ): void {}
		public static function error( $l ): void {}
	}

	spl_autoload_register( static function ( string $class ): void {
		$prefix = 'WMCyber\\Kanzlei\\';
		if ( 0 !== strncmp( $prefix, $class, strlen( $prefix ) ) ) {
			return;
		}
		$file = WM_KANZLEI_PATH . 'includes/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		if ( is_file( $file ) ) {
			require_once $file;
		}
	} );

	use WMCyber\Kanzlei\Admin\AdminDashboard;
	use WMCyber\Kanzlei\API\RestController;
	use WMCyber\Kanzlei\Audit\AuditChain;
	use WMCyber\Kanzlei\CLI\KanzleiCommand;
	use WMCyber\Kanzlei\Core\Settings;
	use WMCyber\Kanzlei\Sanitizer\NerEngine;
	use WMCyber\Kanzlei\Sanitizer\TokenVault;

	require_once WM_KANZLEI_PATH . 'includes/Adapters/Kanzlei_Spoke_Adapter.php';

	// --- Harness -----------------------------------------------------------------------------------------------------
	$passed_count = 0;
	$failed_count = 0;
	function assert_test( string $name, bool $condition, string $details = '' ): void {
		global $passed_count, $failed_count;
		if ( $condition ) {
			echo "  [PASS] {$name}\n";
			++$passed_count;
		} else {
			echo "  [FAIL] {$name}" . ( '' !== $details ? ": {$details}" : '' ) . "\n";
			++$failed_count;
		}
	}
	/** Values of an entity list, "TYPE=value". */
	function k9z_found( array $entities ): array {
		return array_map( static fn( $e ) => $e['type'] . '=' . $e['value'], $entities );
	}

	k9z_reset();
	$ner   = new NerEngine();
	$vault = new TokenVault();

	echo "==============================================================================\n";
	echo "  WM KANZLEI AI SANITIZER — STANDALONE TEST SUITE\n";
	echo "==============================================================================\n\n";

	// ------------------------------------------------------------------------------------------------------------------
	echo "[TEST GROUP 1] Detection: the cases measured on 2026-09-15\n";
	$cases = [
		'Aktenzeichen 2 O 145/23'          => [ 'Im Verfahren 2 O 145/23 vor dem LG Halle.', [ 'AKTENZEICHEN=2 O 145/23' ] ],
		'BGH VI ZR 244/20'                 => [ 'BGH, Urteil vom 12.01.2021 – VI ZR 244/20.', [ 'AKTENZEICHEN=VI ZR 244/20' ] ],
		'BVerfG 1 BvR 102/22'              => [ 'Beschluss 1 BvR 102/22 des BVerfG.', [ 'AKTENZEICHEN=1 BvR 102/22' ] ],
		'BAG 5 AZR 100/23'                 => [ 'BAG 5 AZR 100/23', [ 'AKTENZEICHEN=5 AZR 100/23' ] ],
		'Herrn Müller'                     => [ 'Wir vertreten Herrn Müller in dieser Sache.', [ 'PERSON_NAME=Herrn Müller' ] ],
		'Frau Dr. Schneider'               => [ 'Frau Dr. Schneider ist Zeugin.', [ 'PERSON_NAME=Frau Dr. Schneider' ] ],
		'Rechtsanwältin Weber'             => [ 'Rechtsanwältin Weber zeigt die Vertretung an.', [ 'PERSON_NAME=Rechtsanwältin Weber' ] ],
		'Mandantin Yilmaz'                 => [ 'Die Mandantin Yilmaz wünscht Rückruf.', [ 'PERSON_NAME=Mandantin Yilmaz' ] ],
		'Herr Hans-Peter Schmidt'          => [ 'Herr Hans-Peter Schmidt', [ 'PERSON_NAME=Herr Hans-Peter Schmidt' ] ],
		'Kläger Karl Otto Becker'          => [ 'Kläger Karl Otto Becker', [ 'PERSON_NAME=Kläger Karl Otto Becker' ] ],
		'dem Beklagten Fischer'            => [ 'dem Beklagten Fischer wird aufgegeben', [ 'PERSON_NAME=Beklagten Fischer' ] ],
		'Frau von Bülow'                   => [ 'Frau von Bülow', [ 'PERSON_NAME=Frau von Bülow' ] ],
		'Surname repeated bare'            => [ 'Herr Müller kündigte. Müller verlangt nun Abfindung.', [ 'PERSON_NAME=Herr Müller', 'PERSON_NAME=Müller' ] ],
		'Role nouns are not names'         => [ 'Sehr geehrte Frau Richterin, sehr geehrter Herr Vorsitzender', [] ],
		'+49 345 1234567'                  => [ 'Tel. +49 345 1234567', [ 'PHONE=+49 345 1234567' ] ],
		'+49 (0)345 123456'                => [ 'Tel.: +49 (0)345 123456', [ 'PHONE=+49 (0)345 123456' ] ],
		'50.000,00 € end of sentence'      => [ 'Forderung von 50.000,00 €.', [ 'GELDBETRAG=50.000,00 €' ] ],
		'15.000 € mid sentence'            => [ 'ein Betrag von 15.000 € wurde gezahlt', [ 'GELDBETRAG=15.000 €' ] ],
		'5000 EUR'                         => [ 'Vorschuss 5000 EUR', [ 'GELDBETRAG=5000 EUR' ] ],
		'EUR 3.200,00'                     => [ 'EUR 3.200,00 offen', [ 'GELDBETRAG=EUR 3.200,00' ] ],
		'13-digit number leaves no fragment' => [ 'Steuernummer 3101081512345', [] ],
		'11-digit mobile 01761234567'      => [ 'Tel. 01761234567', [ 'PHONE=01761234567' ] ],
		'11-digit landline 03451234567'    => [ 'Tel. 03451234567', [ 'PHONE=03451234567' ] ],
		'Steuer-ID spaced'                 => [ 'Steuer-ID 12 345 678 901', [ 'STEUER_ID=12 345 678 901' ] ],
		'Steuer-ID valid checksum'         => [ 'Steuer-ID 86 095 742 719', [ 'STEUER_ID=86 095 742 719' ] ],
		'E-mail'                           => [ 'Mail an m.mueller@kanzlei-beispiel.de bitte.', [ 'EMAIL=m.mueller@kanzlei-beispiel.de' ] ],
	];
	foreach ( $cases as $label => [ $text, $expected ] ) {
		$got = k9z_found( $ner->detect_entities( $text ) );
		assert_test( "detects: {$label}", $got === $expected, 'got ' . json_encode( $got, JSON_UNESCAPED_UNICODE ) );
	}
	assert_test( 'steuer_id_checksum_ok accepts valid § 139b AO Steuer-ID 86095742719 and non-consecutive triple 12113456784', true === NerEngine::steuer_id_checksum_ok( '86095742719' ) && true === NerEngine::steuer_id_checksum_ok( '86 095 742 719' ) && true === NerEngine::steuer_id_checksum_ok( '12113456784' ) );
	assert_test( 'steuer_id_checksum_ok rejects 12345678901, 12345678903, bad check digit, leading zero, triple consecutive, two repeated', false === NerEngine::steuer_id_checksum_ok( '12345678901' ) && false === NerEngine::steuer_id_checksum_ok( '12345678903' ) && false === NerEngine::steuer_id_checksum_ok( '86095742718' ) && false === NerEngine::steuer_id_checksum_ok( '06095742719' ) && false === NerEngine::steuer_id_checksum_ok( '11123456786' ) && false === NerEngine::steuer_id_checksum_ok( '11223456785' ) );
	$warn_tax = $ner->collect_review_warnings( 'Steuer-ID 12 345 678 901', $ner->detect_entities( 'Steuer-ID 12 345 678 901' ) );
	assert_test( 'collect_review_warnings flags unverified Steuer-ID checksum', 1 === count( $warn_tax ) && 'steuer_id_unverified_checksum' === $warn_tax[0]['code'] && '12 345 678 901' === $warn_tax[0]['span'] );
	assert_test( 'collect_review_warnings emits no warning for valid Steuer-ID 86 095 742 719', [] === $ner->collect_review_warnings( 'Steuer-ID 86 095 742 719', $ner->detect_entities( 'Steuer-ID 86 095 742 719' ) ) );
	$warn_name = $ner->collect_review_warnings( 'Herr Hans Peter Schmidt Mustermann klagt.', $ner->detect_entities( 'Herr Hans Peter Schmidt Mustermann klagt.' ) );
	assert_test( 'collect_review_warnings flags unredacted capitalised word trailing PERSON_NAME', 1 === count( $warn_name ) && 'possible_trailing_name_word' === $warn_name[0]['code'] && 'Mustermann' === $warn_name[0]['span'] );
	assert_test( 'collect_review_warnings ignores NOT_A_NAME, overlapping entities, and abbreviations like GmbH', [] === $ner->collect_review_warnings( 'Herr Müller Richterin', $ner->detect_entities( 'Herr Müller Richterin' ) ) && [] === $ner->collect_review_warnings( 'Herr Müller Frau Weber', $ner->detect_entities( 'Herr Müller Frau Weber' ) ) && [] === $ner->collect_review_warnings( 'Herr Müller GmbH', $ner->detect_entities( 'Herr Müller GmbH' ) ) );
	$bad = 'Herr Müller, Az. 2 O 145/23, ' . "Gr\xFC\xDFe";
	try {
		$ner->detect_entities( $bad );
		assert_test( 'invalid UTF-8 fails closed (it silently disabled every /u pattern)', false );
	} catch ( Throwable $e ) {
		assert_test( 'invalid UTF-8 fails closed (it silently disabled every /u pattern)', $e instanceof InvalidArgumentException, get_class( $e ) );
	}
	// A pattern that errors must throw, not return what the other patterns found. Without JIT and with a backtrack
	// limit of 50 the text check and the first five patterns pass and the name pattern fails (measured 2026-09-15).
	// In a child process (argument array, no shell): patterns this process already compiled keep their JIT code
	// and ignore the limit.
	$probe = (string) tempnam( sys_get_temp_dir(), 'kz-pcre' );
	file_put_contents( $probe, '<?php define( "ABSPATH", "/" ); require ' . var_export( WM_KANZLEI_PATH . 'includes/Sanitizer/DetectionFailed.php', true ) . '; require ' . var_export( WM_KANZLEI_PATH . 'includes/Sanitizer/NerEngine.php', true ) . '; set_error_handler( static fn() => true ); try { ( new WMCyber\Kanzlei\Sanitizer\NerEngine() )->detect_entities( str_repeat( "Herr Müller zahlt 15.000 € an DE89370400440532013000 und schreibt an a.b@example.org. ", 3 ) ); echo "NO-EXCEPTION"; } catch ( Throwable $e ) { echo get_class( $e ) . ": " . ( $e->type ?? "" ); }' );
	$process = proc_open( [ PHP_BINARY, '-d', 'pcre.jit=0', '-d', 'pcre.backtrack_limit=50', $probe ], [ 1 => [ 'pipe', 'w' ], 2 => [ 'pipe', 'w' ] ], $pipes );
	$child   = is_resource( $process ) ? (string) stream_get_contents( $pipes[1] ) : '';
	if ( is_resource( $process ) ) {
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		proc_close( $process );
	}
	unlink( $probe );
	assert_test( 'a failing pattern throws instead of returning a partial result', str_starts_with( $child, 'WMCyber\\Kanzlei\\Sanitizer\\DetectionFailed' ) && str_contains( $child, 'PERSON_NAME' ), $child );
	$only_iban = k9z_found( $ner->detect_entities( 'Herr Müller zahlt an DE89370400440532013000.', [ 'IBAN' ] ) );
	assert_test( 'a type list limits what is reported', [ 'IBAN=DE89370400440532013000' ] === $only_iban, json_encode( $only_iban, JSON_UNESCAPED_UNICODE ) );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 2] IBAN: check digits, case, separators, trailing words\n";
	foreach ( [ 'DE89370400440532013000', 'AT611904300234573201', 'FR1420041010050500013M02606', 'GB29NWBK60161331926819' ] as $iban ) {
		assert_test( "mod-97 accepts {$iban}", NerEngine::iban_checksum_ok( $iban ) );
	}
	assert_test( 'mod-97 refuses a changed digit', ! NerEngine::iban_checksum_ok( 'DE89370400440532013001' ) );
	$iban_cases = [
		'lowercase spaced'  => [ 'iban de89 3704 0044 0532 0130 00 bitte', 'IBAN=de89 3704 0044 0532 0130 00' ],
		'hyphenated'        => [ 'Konto DE89-3704-0044-0532-0130-00.', 'IBAN=DE89-3704-0044-0532-0130-00' ],
		'uppercase words'   => [ 'IBAN DE89370400440532013000 BITTE BIS MONTAG', 'IBAN=DE89370400440532013000' ],
		'invalid checksum'  => [ 'IBAN ES21 0000 1111 2222 bitte', 'IBAN=ES21 0000 1111 2222' ],
		// "FR…606 bis" passes mod-97 as a whole; the word must not become part of the IBAN.
		'word passing mod-97' => [ 'an FR1420041010050500013M02606 bis heute', 'IBAN=FR1420041010050500013M02606' ],
		'word inside group'   => [ 'an FR1420041010050500013M02606 b', 'IBAN=FR1420041010050500013M02606' ],
		// A number group after the IBAN is cut off by the check digits, not by the word rule.
		'number group after' => [ 'Konto DE89 3704 0044 0532 0130 00 12 Monate', 'IBAN=DE89 3704 0044 0532 0130 00' ],
		// Digits glued to an IBAN: no separator to cut at, so the whole run is replaced rather than a readable tail left.
		'digits glued on'    => [ 'Konto DE89370400440532013000123 ab', 'IBAN=DE89370400440532013000123' ],
	];
	foreach ( $iban_cases as $label => [ $text, $expected ] ) {
		$got = k9z_found( $ner->detect_entities( $text ) );
		assert_test( "IBAN {$label}: whole value, no PHONE fragment", [ $expected ] === $got, json_encode( $got, JSON_UNESCAPED_UNICODE ) );
	}

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 3] Placeholders and rehydration\n";
	$text      = 'Herr Müller kündigte. Müller zahlt 15.000 € an DE89370400440532013000.';
	$entities  = $ner->detect_entities( $text );
	$tok       = $vault->tokenize( $text, $entities, 'salt-a' );
	$tok_b     = $vault->tokenize( $text, $entities, 'salt-b' );
	assert_test( 'no detected value survives', ! str_contains( $tok['sanitized_text'], 'Müller' ) && ! str_contains( $tok['sanitized_text'], 'DE89' ) && ! str_contains( $tok['sanitized_text'], '15.000' ), $tok['sanitized_text'] );
	assert_test( 'placeholders carry 16 hex characters (they had 8, a 32-bit space)', preg_match_all( '/\{\{[A-Z_]+_[0-9a-f]{16}\}\}/', $tok['sanitized_text'] ) >= 1 &&0 === preg_match( '/\{\{[A-Z_]+_[0-9a-f]{8}\}\}/', $tok['sanitized_text'] ), $tok['sanitized_text'] );
	assert_test( 'every mapping key has the placeholder shape', TokenVault::is_valid_mapping( $tok['mapping'] ) );
	assert_test( 'another salt gives other placeholders', array_keys( $tok['mapping'] ) !== array_keys( $tok_b['mapping'] ) );
	assert_test( 'the round trip restores the text', $text === $vault->rehydrate( $tok['sanitized_text'], $tok['mapping'] ) );
	foreach ( [ 'list' => [ 'a', 'b' ], 'numeric key' => [ 123 => 'v' ], 'array value' => [ '{{IBAN_0123456789abcdef}}' => [ 'v' ] ], 'int value' => [ '{{IBAN_0123456789abcdef}}' => 5 ], 'string' => 'oops', 'free key' => [ 'Müller' => 'x' ] ] as $label => $mapping ) {
		assert_test( "a malformed mapping ({$label}) is refused", ! TokenVault::is_valid_mapping( $mapping ) );
	}
	try {
		$out = $vault->rehydrate( 'x {{IBAN_0123456789abcdef}}', [ 123 => 'v', '{{IBAN_0123456789abcdef}}' => [ 'v' ] ] );
		assert_test( 'rehydrate skips malformed pairs instead of a TypeError', 'x {{IBAN_0123456789abcdef}}' === $out, $out );
	} catch ( Throwable $e ) {
		assert_test( 'rehydrate skips malformed pairs instead of a TypeError', false, get_class( $e ) );
	}

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 4] REST routes\n";
	k9z_reset();
	$GLOBALS['mock_routes'] = [];
	$rest = new RestController( $ner, $vault );
	$rest->register();
	$r = $GLOBALS['mock_routes'];
	assert_test( 'five routes registered', 5 === count( $r ), implode( ', ', array_keys( $r ) ) );
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true ];
	assert_test( '/sanitize and /rehydrate need edit_posts, /audit-log manage_options', $r['wm-kanzlei/v1/sanitize']['permission_callback']() && ! $r['wm-kanzlei/v1/audit-log']['permission_callback']() );
	assert_test( '/sanitize declares prompt as a required string', 'string' === ( $r['wm-kanzlei/v1/sanitize']['args']['prompt']['type'] ?? '' ) && ! empty( $r['wm-kanzlei/v1/sanitize']['args']['prompt']['required'] ) );
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true, 'manage_options' => true ];

	$proxy = $rest->proxy_not_available( new WP_REST_Request( [ 'prompt' => 'Herr Müller' ] ) );
	assert_test( '/proxy answers 501 and returns no completion (it returned a fixed legal opinion)', $proxy instanceof WP_Error && 501 === ( $proxy->data['status'] ?? 0 ) );
	$proxy_src = (string) file_get_contents( WM_KANZLEI_PATH . 'includes/API/RestController.php' );
	assert_test( 'no code path returns "stgb_203_certified" or "zero_pii_retention"', ! str_contains( $proxy_src, "'stgb_203_certified'" ) && ! str_contains( $proxy_src, "'zero_pii_retention'" ) && ! str_contains( $proxy_src, 'WENDER_MEDIA_SECRET_GATE' ) );

	$zero = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => '0' ] ) );
	assert_test( 'the prompt "0" is accepted (empty() refused it)', $zero instanceof WP_REST_Response && true === $zero->data['success'] );
	$enc = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => "Gr\xFC\xDFe Herr Müller" ] ) );
	assert_test( 'invalid UTF-8 gives 400, nothing replaced or stored beyond the "0" call', $enc instanceof WP_Error && 400 === ( $enc->data['status'] ?? 0 ) && 1 === count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_sessions'] ) );

	$ok = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Herr Müller zahlt an DE89370400440532013000.' ] ) );
	assert_test( '/sanitize replaces, returns the mapping and an audit id', $ok instanceof WP_REST_Response && ! str_contains( $ok->data['sanitized_text'], 'Müller' ) && 2 === count( $ok->data['mapping'] ) && $ok->data['audit_id'] > 0 && [] === ( $ok->data['review_warnings'] ?? null ) );
	$warn_rest = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Steuer-ID 12 345 678 901; Herr Hans Peter Schmidt Mustermann.' ] ) );
	$warn_list = $warn_rest instanceof WP_REST_Response && is_array( $warn_rest->data['review_warnings'] ?? null ) ? $warn_rest->data['review_warnings'] : [];
	assert_test( '/sanitize surfaces review_warnings while redacting fail-safe', $warn_rest instanceof WP_REST_Response && ! str_contains( $warn_rest->data['sanitized_text'], '12 345 678 901' ) && 2 === count( $warn_list ) && [ 'steuer_id_unverified_checksum', 'possible_trailing_name_word' ] === array_column( $warn_list, 'code' ) );
	$audit_row = end( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_audit_log'] );
	assert_test( 'the audit row is sealed and chained (previous_hash was sha256("INIT") on every row)', $audit_row['previous_hash'] !== hash( 'sha256', 'INIT' ) && 64 === strlen( $audit_row['current_hash'] ) && 'NONE' === $audit_row['compliance_standard'] );

	update_option( Settings::OPTION, [ 'redact_iban' => false, 'alert_email' => 'keep@example.test' ] );
	$no_iban = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Herr Müller zahlt an DE89370400440532013000.' ] ) );
	assert_test( 'a switched-off type stays in the text (the settings were never read)', str_contains( $no_iban->data['sanitized_text'], 'DE89370400440532013000' ) && ! str_contains( $no_iban->data['sanitized_text'], 'Müller' ) && ! in_array( 'IBAN', $no_iban->data['types_checked'], true ) );
	delete_option( Settings::OPTION );

	$sessions_before = count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_sessions'] );
	$tip_before      = get_option( AuditChain::TIP_OPTION );
	$GLOBALS['wpdb']->lock_answer = '0';
	$locked = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Herr Müller' ] ) );
	$GLOBALS['wpdb']->lock_answer = '1';
	assert_test( 'without the chain lock: 503, no text returned, session row removed, tip unchanged', $locked instanceof WP_Error && 503 === ( $locked->data['status'] ?? 0 ) && count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_sessions'] ) === $sessions_before && get_option( AuditChain::TIP_OPTION ) === $tip_before );
	$GLOBALS['wpdb']->refuse_insert = true;
	$refused = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Herr Müller' ] ) );
	$GLOBALS['wpdb']->refuse_insert = false;
	assert_test( 'a refused session insert gives 503 and nothing is returned', $refused instanceof WP_Error && 503 === ( $refused->data['status'] ?? 0 ) );

	$bad_map = $rest->rehydrate_response( new WP_REST_Request( [ 'response' => 'x', 'mapping' => [ 'a', 'b' ] ] ) );
	assert_test( '/rehydrate with a malformed mapping gives 400 (it was an HTTP 500 TypeError)', $bad_map instanceof WP_Error && 400 === ( $bad_map->data['status'] ?? 0 ) );
	$good_map = $rest->rehydrate_response( new WP_REST_Request( [ 'response' => 'Antwort für ' . array_key_first( $ok->data['mapping'] ), 'mapping' => $ok->data['mapping'] ] ) );
	assert_test( '/rehydrate restores from a valid mapping', $good_map instanceof WP_REST_Response && str_contains( $good_map->data['rehydrated_text'], (string) reset( $ok->data['mapping'] ) ) );

	$unknown = $rest->get_session_record( new WP_REST_Request( [ 'session_id' => 'never-existed-123' ] ) );
	assert_test( '/certificate for an unknown session: 404 (it issued a certificate)', $unknown instanceof WP_Error && 404 === ( $unknown->data['status'] ?? 0 ) );
	$record = $rest->get_session_record( new WP_REST_Request( [ 'session_id' => $ok->data['session_id'] ] ) );
	assert_test( '/certificate for a real session returns its record and chain status, no statute', $record instanceof WP_REST_Response && 'session_record' === $record->data['record_type'] && ! isset( $record->data['standard'] ) && 'INTACT' === $record->data['chain_status'] && true === $record->data['audit']['sealed'] );
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true ];
	$GLOBALS['mock_user'] = 99;
	$other = $rest->get_session_record( new WP_REST_Request( [ 'session_id' => $ok->data['session_id'] ] ) );
	assert_test( 'another non-admin user gets 403 for someone else\'s session', $other instanceof WP_Error && 403 === ( $other->data['status'] ?? 0 ) );
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true, 'manage_options' => true ];
	$GLOBALS['mock_user'] = 7;
	$log = $rest->get_audit_log( new WP_REST_Request() );
	assert_test( '/audit-log returns the rows, the total and the chain result', $log->data['total'] === count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_audit_log'] ) && 'INTACT' === $log->data['chain']['status'] && ! array_key_exists( 'compliance_standard', $log->data['logs'][0] ) );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 5] Audit chain\n";
	k9z_reset();
	$t = 'wp_wm_kanzlei_audit_log';
	assert_test( 'empty table, no tip: EMPTY_CHAIN', 'EMPTY_CHAIN' === AuditChain::verify()['status'] );
	foreach ( [ 1, 2 ] as $n ) {
		$GLOBALS['wpdb']->insert( $t, [ 'session_id' => "demo{$n}", 'action' => 'PROMPT_SANITIZE', 'entity_types_summary' => 'MANDANT (Dr. Hans Schmidt)', 'compliance_standard' => '§ 203 StGB', 'previous_hash' => '', 'current_hash' => '', 'created_at' => '2026-08-26 23:56:13' ] );
	}
	$legacy = AuditChain::verify();
	assert_test( 'only rows from before the chain: UNCHAINED_ONLY with 2 unchained, not INTACT', 'UNCHAINED_ONLY' === $legacy['status'] && 2 === $legacy['unchained'] );
	$a1 = AuditChain::append( 's1', 'PROMPT_SANITIZATION', 'IBAN', '2026-09-15 10:00:00' );
	$a2 = AuditChain::append( 's2', 'PROMPT_SANITIZATION', 'NONE', '2026-09-15 10:01:00' );
	$a3 = AuditChain::append( 's3', 'PROMPT_SANITIZATION', 'EMAIL', '2026-09-15 10:02:00' );
	$rows = $GLOBALS['wpdb']->tables[ $t ];
	assert_test( 'the first sealed row chains onto genesis, each next one onto its predecessor', AuditChain::GENESIS_HASH === $rows[ $a1['id'] ]['previous_hash'] && $rows[ $a1['id'] ]['current_hash'] === $rows[ $a2['id'] ]['previous_hash'] && $rows[ $a2['id'] ]['current_hash'] === $rows[ $a3['id'] ]['previous_hash'] );
	$ok_chain = AuditChain::verify();
	assert_test( 'legacy rows then three sealed rows: INTACT, 3 checked, 2 unchained', 'INTACT' === $ok_chain['status'] && 3 === $ok_chain['checked'] && 2 === $ok_chain['unchained'], json_encode( $ok_chain ) );
	assert_test( 'the tip option holds the newest seal', get_option( AuditChain::TIP_OPTION ) === $a3['seal'] );

	$snapshot = $GLOBALS['wpdb']->tables[ $t ];
	$GLOBALS['wpdb']->tables[ $t ][ $a2['id'] ]['entity_types_summary'] = 'IBAN';
	$edited = AuditChain::verify();
	assert_test( 'an edited field breaks the chain at that row', 'BROKEN' === $edited['status'] && $a2['id'] === $edited['broken_id'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	unset( $GLOBALS['wpdb']->tables[ $t ][ $a2['id'] ] );
	$deleted = AuditChain::verify();
	assert_test( 'a deleted middle row breaks the chain', 'BROKEN' === $deleted['status'] && $a3['id'] === $deleted['broken_id'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	unset( $GLOBALS['wpdb']->tables[ $t ][ $a2['id'] ] );
	$GLOBALS['wpdb']->tables[ $t ][ $a3['id'] ]['previous_hash'] = $snapshot[ $a1['id'] ]['current_hash'];
	assert_test( 'a deleted row bridged by rewriting previous_hash still breaks (the seal binds the previous seal)', 'BROKEN' === AuditChain::verify()['status'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	unset( $GLOBALS['wpdb']->tables[ $t ][ $a3['id'] ] );
	assert_test( 'removing the newest row is caught by the recorded tip', 'BROKEN' === AuditChain::verify()['status'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	$GLOBALS['wpdb']->insert( $t, [ 'session_id' => 'late', 'action' => 'X', 'entity_types_summary' => 'NONE', 'compliance_standard' => 'NONE', 'previous_hash' => '', 'current_hash' => '', 'created_at' => '2026-09-15 11:00:00' ] );
	assert_test( 'an unsealed row after the chain started breaks it', 'BROKEN' === AuditChain::verify()['status'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	$GLOBALS['mock_salt_suffix'] = '-other-site';
	assert_test( 'other salts (a copied database) verify as BROKEN', 'BROKEN' === AuditChain::verify()['status'] );
	unset( $GLOBALS['mock_salt_suffix'] );
	$GLOBALS['wpdb']->tables[ $t ] = [];
	assert_test( 'all rows removed while the tip stays: BROKEN, not EMPTY_CHAIN', 'BROKEN' === AuditChain::verify()['status'] );
	$GLOBALS['wpdb']->tables[ $t ] = $snapshot;
	delete_option( AuditChain::TIP_OPTION );
	assert_test( 'sealed rows without the recorded tip: BROKEN', 'BROKEN' === AuditChain::verify()['status'] );
	update_option( AuditChain::TIP_OPTION, $a3['seal'] );
	$count_before = count( $GLOBALS['wpdb']->tables[ $t ] );
	$GLOBALS['wpdb']->lock_answer = '0';
	$nolock = AuditChain::append( 's4', 'PROMPT_SANITIZATION', 'NONE', '2026-09-15 10:03:00' );
	$GLOBALS['wpdb']->lock_answer = '1';
	assert_test( 'no lock: nothing appended, tip unchanged', false === $nolock['ok'] && count( $GLOBALS['wpdb']->tables[ $t ] ) === $count_before && get_option( AuditChain::TIP_OPTION ) === $a3['seal'] );
	$GLOBALS['wpdb']->refuse_insert = true;
	$refused_row = AuditChain::append( 's5', 'PROMPT_SANITIZATION', 'NONE', '2026-09-15 10:04:00' );
	$GLOBALS['wpdb']->refuse_insert = false;
	assert_test( 'refused insert: not ok, tip unchanged, lock released', false === $refused_row['ok'] && get_option( AuditChain::TIP_OPTION ) === $a3['seal'] && [] === $GLOBALS['wpdb']->locks );
	unset( $GLOBALS['wpdb']->tables[ $t ] );
	assert_test( 'a missing table: BROKEN, not EMPTY_CHAIN', 'BROKEN' === AuditChain::verify()['status'] );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 6] Settings\n";
	k9z_reset();
	assert_test( 'no option: every type is replaced', NerEngine::TYPES === array_values( array_intersect( NerEngine::TYPES, Settings::enabled_types() ) ) && 7 === count( Settings::enabled_types() ) );
	update_option( Settings::OPTION, [ 'llm_provider' => 'openai', 'retention_minutes' => 60, 'alert_email' => 'keep@example.test', 'redact_names' => true ] );
	Settings::save_switches( [ 'redact_names' => '', 'redact_iban' => '1' ] );
	$stored = get_option( Settings::OPTION );
	assert_test( 'a save keeps keys the form does not carry (alert_email was reset on every save)', 'keep@example.test' === $stored['alert_email'] && 60 === $stored['retention_minutes'] );
	assert_test( 'an unticked switch is stored off and leaves its type out', false === $stored['redact_names'] && ! in_array( 'PERSON_NAME', Settings::enabled_types(), true ) && in_array( 'IBAN', Settings::enabled_types(), true ) );
	Settings::enable_all();
	assert_test( '"all types on" switches everything on', 7 === count( Settings::enabled_types() ) );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 7] WP-CLI\n";
	k9z_reset();
	$r1 = KanzleiCommand::report( 'Zahlung an DE89370400440532013000' );
	$r2 = KanzleiCommand::report( 'Zahlung an DE89370400440532013000' );
	assert_test( 'a random salt per run (the fixed salt gave the same placeholder every time)', $r1['sanitized'] !== $r2['sanitized'] );
	assert_test( 'values are printed masked, never in clear', ! str_contains( implode( "\n", array_slice( $r1['lines'], 0, -1 ) ), 'DE89370400440532013000' ) && str_contains( implode( "\n", $r1['lines'] ), 'DE********************' ) );
	assert_test( 'nothing found is reported as 0', 0 === KanzleiCommand::report( 'Guten Tag.' )['count'] );
	$cli_src = (string) file_get_contents( WM_KANZLEI_PATH . 'includes/CLI/KanzleiCommand.php' );
	assert_test( 'no --rehydrate option documented and no "vaulted" success', 0 === preg_match( '/\[--rehydrate/', $cli_src ) && 0 === preg_match( '/success\([^;]*vaulted/', $cli_src ) );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 8] Hub adapter\n";
	k9z_reset();
	$adapter = new \WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter();
	assert_test( 'HEALTHY with tables, an empty chain and a passing self-test', 'HEALTHY' === $adapter->get_health_status() );
	$self = $adapter->execute_action( 'self_test' );
	assert_test( 'the self-test finds its five sample types and says so', true === $self['success'] && str_contains( $self['message'], 'bestanden' ) && str_contains( $self['message'], 'PERSON_NAME' ) );
	$weak      = new \WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter( static fn( string $text ): array => [ [ 'type' => 'IBAN', 'value' => 'x', 'start' => 0, 'length' => 1 ] ] );
	$weak_self = $weak->execute_action( 'self_test' );
	assert_test( 'a detector that misses types fails the self-test and the message says which (it said "erfolgreich" regardless)', false === $weak_self['success'] && str_contains( $weak_self['message'], 'fehlgeschlagen' ) && str_contains( $weak_self['message'], 'AKTENZEICHEN' ) && 'ERROR' === $weak->get_health_status() );
	unset( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_audit_log'] );
	assert_test( 'ERROR without the audit table (the health was the literal HEALTHY)', 'ERROR' === $adapter->get_health_status() );
	k9z_reset();
	AuditChain::append( 's1', 'PROMPT_SANITIZATION', 'IBAN', '2026-09-15 10:00:00' );
	update_option( AuditChain::TIP_OPTION, str_repeat( 'a', 64 ) );
	assert_test( 'ERROR with a broken chain', 'ERROR' === $adapter->get_health_status() && 'BROKEN' === $adapter->get_telemetry_metrics()['audit_chain_status'] );
	assert_test( 'the settings link opens the plugin page (page=wm-kanzlei-dashboard did not exist)', str_contains( (string) $adapter->get_settings_url(), 'page=wm-kanzlei-sanitizer' ) );
	$sbom = json_encode( $adapter->get_sbom_data(), JSON_UNESCAPED_UNICODE );
	assert_test( 'SBOM and description carry no compliance properties or statutes', ! str_contains( $sbom, 'wm:compliance' ) && ! str_contains( $sbom, '§' ) && ! str_contains( $adapter->get_description(), '§' ) );
	assert_test( 'an unknown action is plain text', 'Unbekannte Spoke-Aktion "x"<b>".' === $adapter->execute_action( 'x"<b>' )['message'] );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 9] Admin screen\n";
	k9z_reset();
	$admin = new AdminDashboard( $ner, $vault );
	$GLOBALS['wpdb']->insert( 'wp_wm_kanzlei_sessions', [ 'session_id' => 'a', 'operator_id' => 7, 'entities_redacted' => 3, 'prompt_tokens_est' => 1, 'created_at' => 'x' ] );
	$GLOBALS['wpdb']->insert( 'wp_wm_kanzlei_sessions', [ 'session_id' => 'b', 'operator_id' => 7, 'entities_redacted' => 4, 'prompt_tokens_est' => 1, 'created_at' => 'x' ] );
	$pages = [];
	foreach ( [ 'overview', 'simulator', 'settings', 'log', 'help' ] as $tab ) {
		$_GET = [ 'page' => AdminDashboard::PAGE, 'tab' => $tab ];
		ob_start();
		$admin->render_dashboard_page();
		$pages[ $tab ] = (string) ob_get_clean();
	}
	ob_start();
	$admin->render_dashboard_widget();
	$widget = (string) ob_get_clean();
	$all    = implode( '', $pages ) . $widget;
	assert_test( 'counts come from the tables (widget: 2 calls, 7 values)', str_contains( $widget, '>2<' ) && str_contains( $widget, '>7<' ) );
	assert_test( 'no emoji anywhere on the screen', 0 === preg_match( '/[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]/u', $all ) );
	foreach ( [ 'COMPLIANT', 'CUSTODIA', 'ANONIMIZACI', '100%', 'Anonymisierung vor', '0 Cloud', 'encript' ] as $claim ) {
		assert_test( "no claim \"{$claim}\"", ! str_contains( $all, $claim ) );
	}
	assert_test( 'no inline hex colour', 0 === preg_match( '/style="[^"]*#[0-9a-fA-F]{3,6}/', $all ) );
	assert_test( 'the overview names what is not detected', str_contains( $pages['overview'], 'Nicht erkannt werden' ) );
	assert_test( 'no provider or retention field in the settings', ! str_contains( $pages['settings'], 'llm_provider' ) && ! str_contains( $pages['settings'], 'retention_minutes' ) );
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true ];
	$_GET = [ 'page' => AdminDashboard::PAGE, 'tab' => 'log' ];
	ob_start();
	$admin->render_dashboard_page();
	$editor_log = (string) ob_get_clean();
	assert_test( 'an editor asking for the log gets the overview, without the log tab (the log was shown to edit_posts)', ! str_contains( $editor_log, 'Gefundene Typen' ) && ! str_contains( $editor_log, 'tab=log' ) );
	$_POST = [ 'wm_kanzlei_action' => 'save_settings', 'wm_kanzlei_nonce' => 'nonce-wm_kanzlei_save_settings' ];
	try {
		$admin->handle_form_actions();
		assert_test( 'an editor cannot save settings', false );
	} catch ( RuntimeException $e ) {
		assert_test( 'an editor cannot save settings', str_contains( $e->getMessage(), 'wp_die' ) );
	}
	$GLOBALS['mock_caps'] = [ 'edit_posts' => true, 'manage_options' => true ];
	update_option( Settings::OPTION, [ 'alert_email' => 'keep@example.test' ] );
	$_POST = [ 'wm_kanzlei_action' => 'save_settings', 'wm_kanzlei_nonce' => 'nonce-wm_kanzlei_save_settings', 'redact_iban' => '1' ];
	try {
		$admin->handle_form_actions();
	} catch ( K9z_Redirect $e ) {
	}
	assert_test( 'saving through the form keeps alert_email and stores unticked switches off', 'keep@example.test' === get_option( Settings::OPTION )['alert_email'] && false === get_option( Settings::OPTION )['redact_names'] );
	$_POST = [ 'wm_kanzlei_action' => 'save_settings', 'wm_kanzlei_nonce' => 'nonce-wm_kanzlei_enable_all' ];
	try {
		$admin->handle_form_actions();
		assert_test( 'the settings form refuses another form\'s nonce', false );
	} catch ( K9z_Redirect $e ) {
		assert_test( 'the settings form refuses another form\'s nonce', false );
	} catch ( RuntimeException $e ) {
		assert_test( 'the settings form refuses another form\'s nonce', 'bad nonce' === $e->getMessage() );
	}
	delete_option( Settings::OPTION );
	$rows_before = count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_audit_log'] );
	$_POST       = [ 'wm_kanzlei_action' => 'seed_demo_data', 'wm_kanzlei_nonce' => 'nonce-wm_kanzlei_admin_action' ];
	try {
		$admin->handle_form_actions();
	} catch ( Throwable $e ) {
	}
	assert_test( 'the demo seeder is gone: no rows written into the audit log', count( $GLOBALS['wpdb']->tables['wp_wm_kanzlei_audit_log'] ) === $rows_before );
	$_POST = [ 'wm_kanzlei_sim_nonce' => 'nonce-wm_kanzlei_sim', 'wm_sim_prompt' => 'Streitwert 14.500 EUR, Herr Müller.' ];
	$sim   = $admin->simulate();
	$md5   = '{{GELDBETRAG_' . substr( md5( '14.500 EUR' ), 0, 8 ) . '}}';
	$sim_again = $admin->simulate();
	assert_test( 'the simulator uses salted 16-hex placeholders (md5 prefixes let "14.500 EUR" be recovered)', null !== $sim['result'] && ! str_contains( $sim['result']['tokenized']['sanitized_text'], $md5 ) && 2 === preg_match_all( '/\{\{[A-Z_]+_[0-9a-f]{16}\}\}/', $sim['result']['tokenized']['sanitized_text'] ) );
	assert_test( 'the simulator salt is random per run (the same text gives other placeholders)', $sim['result']['tokenized']['sanitized_text'] !== $sim_again['result']['tokenized']['sanitized_text'] );
	$_POST = [ 'wm_kanzlei_sim_nonce' => 'nonce-wm_kanzlei_sim', 'wm_sim_prompt' => 'Steuer-ID 12 345 678 901; Herr Hans Peter Schmidt Mustermann.' ];
	$sim_warn = $admin->simulate();
	$_GET = [ 'page' => AdminDashboard::PAGE, 'tab' => 'simulator' ];
	ob_start();
	$admin->render_dashboard_page();
	$sim_warn_html = (string) ob_get_clean();
	assert_test( 'the simulator computes warnings and renders an inline notice-warning box', null !== $sim_warn['result'] && 2 === count( $sim_warn['result']['warnings'] ) && str_contains( $sim_warn_html, 'notice-warning' ) && str_contains( $sim_warn_html, '12 345 678 901' ) && str_contains( $sim_warn_html, 'Mustermann' ) );
	$_POST = [ 'wm_kanzlei_sim_nonce' => 'nonce-wm_kanzlei_sim', 'wm_sim_prompt' => 'Steuer-ID 86 095 742 719.' ];
	ob_start();
	$admin->render_dashboard_page();
	$sim_clean_html = (string) ob_get_clean();
	assert_test( 'the simulator renders no notice-warning box when checksum is valid', ! str_contains( $sim_clean_html, 'notice-warning' ) );
	$_POST = [ 'wm_kanzlei_sim_nonce' => 'nonce-wm_kanzlei_sim', 'wm_sim_prompt' => "Gr\xFC\xDFe" ];
	assert_test( 'the simulator shows the encoding error instead of a clean result', null !== $admin->simulate()['error'] );
	$admin->register_settings();
	assert_test( 'register_setting registers wm_kanzlei_delete_data_on_uninstall', isset( $GLOBALS['mock_registered_settings'][ Settings::DELETE_DATA_OPTION ] ) );
	assert_test( 'settings tab renders the opt-in uninstall checkbox', str_contains( $pages['settings'], Settings::DELETE_DATA_OPTION ) );
	$_POST = [ 'wm_kanzlei_action' => 'save_settings', 'wm_kanzlei_nonce' => 'nonce-wm_kanzlei_save_settings', Settings::DELETE_DATA_OPTION => '1' ];
	try {
		$admin->handle_form_actions();
	} catch ( K9z_Redirect $e ) {
	}
	assert_test( 'saving settings stores the opt-in uninstall checkbox when ticked', true === Settings::delete_data_on_uninstall() );
	$_POST = [];
	$_GET  = [];

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 10] Boot, request report, hooks and ecosystem bridges\n";
	$plugin_code = '';
	foreach ( token_get_all( (string) file_get_contents( WM_KANZLEI_PATH . 'includes/Core/Plugin.php' ) ) as $token ) {
		$plugin_code .= is_array( $token ) ? ( in_array( $token[0], [ T_COMMENT, T_DOC_COMMENT ], true ) ? '' : $token[1] ) : $token;
	}
	assert_test( 'boot no longer creates uploads/wm-kanzlei/vault on every request', ! str_contains( $plugin_code, 'protect(' ) && ! is_file( WM_KANZLEI_PATH . 'includes/Security/DirectoryProtector.php' ) );
	$shield_src = (string) file_get_contents( WM_KANZLEI_PATH . 'includes/Security/RequestShield.php' );
	assert_test( 'the error-log line carries no client IP and does not say "BLOCK"', 1 === preg_match( "/error_log\( sprintf\( '([^']+)'/", $shield_src, $m ) && ! str_contains( $m[1], 'IP' ) && ! str_contains( $m[1], 'BLOCK' ) );
	assert_test( 'RequestShield guards error_log behind WP_DEBUG on the same line', 1 === preg_match( "/defined\( 'WP_DEBUG' \) && WP_DEBUG && function_exists\( 'error_log' \)[^\n]+error_log\(/", $shield_src ) );
	$schema_src = (string) file_get_contents( WM_KANZLEI_PATH . 'includes/Database/Schema.php' );
	assert_test( 'Schema.php has the direct-access guard', str_contains( $schema_src, "defined( 'ABSPATH' )" ) );

	k9z_reset();
	require_once WM_KANZLEI_FILE;
	$init_site_hooks = $GLOBALS['mock_actions']['wp_initialize_site'] ?? [];
	assert_test( 'wp_initialize_site hook is registered in main plugin file', [] !== $init_site_hooks );
	$GLOBALS['mock_multisite']      = true;
	$GLOBALS['mock_network_active'] = true;
	if ( [] !== $init_site_hooks ) {
		( $init_site_hooks[0] )( (object) [ 'blog_id' => 3 ] );
	}
	assert_test( 'wp_initialize_site creates tables for network-activated subsite and restores blog', array_key_exists( 'wp_3_wm_kanzlei_sessions', $GLOBALS['wpdb']->tables ) && array_key_exists( 'wp_3_wm_kanzlei_audit_log', $GLOBALS['wpdb']->tables ) && 'wp_' === $GLOBALS['wpdb']->prefix );
	$GLOBALS['mock_network_active'] = false;
	if ( [] !== $init_site_hooks ) {
		( $init_site_hooks[0] )( (object) [ 'blog_id' => 4 ] );
	}
	assert_test( 'wp_initialize_site skips subsite when plugin is not network-activated', ! array_key_exists( 'wp_4_wm_kanzlei_sessions', $GLOBALS['wpdb']->tables ) && ! array_key_exists( 'wp_4_wm_kanzlei_audit_log', $GLOBALS['wpdb']->tables ) );
	$GLOBALS['mock_site_ids'] = [ 1, 2 ];
	\WMCyber\Kanzlei\Database\Schema::activate( true );
	assert_test( 'Schema::activate(true) creates tables across existing multisite blogs and restores blog', array_key_exists( 'wp_2_wm_kanzlei_sessions', $GLOBALS['wpdb']->tables ) && array_key_exists( 'wp_2_wm_kanzlei_audit_log', $GLOBALS['wpdb']->tables ) && 'wp_' === $GLOBALS['wpdb']->prefix );

	k9z_reset();
	\WMCyber\Kanzlei\Core\Plugin::instance()->boot();
	assert_test( 'Plugin::boot() fires wm_kanzlei_ready with the Plugin instance', ! empty( $GLOBALS['mock_dispatched_actions']['wm_kanzlei_ready'] ) && $GLOBALS['mock_dispatched_actions']['wm_kanzlei_ready'][0][0] instanceof \WMCyber\Kanzlei\Core\Plugin );

	add_filter(
		'wm_kanzlei_entity_patterns',
		static fn( array $patterns ): array => $patterns + [ 'MANDATS_AZ' => '/\b\d{4}\/\d{4}-[A-Z]{2}\b/' ],
		10,
		3
	);
	$custom_entities = $ner->detect_entities( 'Internes Zeichen 2024/0815-MK prüfen.' );
	$custom_tok      = $vault->tokenize( 'Internes Zeichen 2024/0815-MK prüfen.', $custom_entities, 'custom-salt' );
	assert_test( 'wm_kanzlei_entity_patterns adds custom entity patterns that tokenize and rehydrate cleanly', [ 'MANDATS_AZ=2024/0815-MK' ] === k9z_found( $custom_entities ) && ! str_contains( $custom_tok['sanitized_text'], '2024/0815-MK' ) && 'Internes Zeichen 2024/0815-MK prüfen.' === $vault->rehydrate( $custom_tok['sanitized_text'], $custom_tok['mapping'] ) );

	k9z_reset();
	add_filter(
		'wm_kanzlei_sanitized_result',
		static function ( array $payload ): array {
			$payload['custom_tag'] = 'filtered-ok';
			return $payload;
		},
		10,
		3
	);
	$filtered_res = $rest->sanitize_prompt( new WP_REST_Request( [ 'prompt' => 'Herr Müller' ] ) );
	assert_test( 'wm_kanzlei_sanitized_result filters the /sanitize response payload', $filtered_res instanceof WP_REST_Response && 'filtered-ok' === ( $filtered_res->data['custom_tag'] ?? '' ) );

	k9z_reset();
	$GLOBALS['wpdb']->insert( 'wp_wm_kanzlei_sessions', [ 'session_id' => 'b1', 'operator_id' => 7, 'entities_redacted' => 5, 'prompt_tokens_est' => 1, 'created_at' => 'x' ] );
	$bridge = new \WMCyber\Kanzlei\Integrations\EcosystemBridge();
	$bridge->register_block_bindings();
	$bridge->register_generateblocks_tag();
	assert_test( 'EcosystemBridge registers WP 6.5+ Block Bindings source wm-kanzlei/stats', isset( $GLOBALS['mock_block_bindings']['wm-kanzlei/stats'] ) && '5' === ( $GLOBALS['mock_block_bindings']['wm-kanzlei/stats']['get_value_callback'] )( [ 'key' => 'replaced' ] ) && null === ( $GLOBALS['mock_block_bindings']['wm-kanzlei/stats']['get_value_callback'] )( [ 'key' => 'unknown' ] ) );
	assert_test( 'EcosystemBridge registers GenerateBlocks 2.x Dynamic Tag wm_kanzlei_stat', 1 === count( GenerateBlocks_Register_Dynamic_Tag::$registered ) && 'wm_kanzlei_stat' === GenerateBlocks_Register_Dynamic_Tag::$registered[0]['tag'] && '1' === ( GenerateBlocks_Register_Dynamic_Tag::$registered[0]['return'] )( [ 'key' => 'sessions' ] ) && null === $bridge->filter_generateblocks_replacement( null, [ 'tag' => 'other_tag' ] ) );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 11] Uninstall (D-UNINSTALL opt-in)\n";
	k9z_reset();
	update_option( 'wm_kanzlei_settings', [ 'redact_iban' => true ] );
	update_option( AuditChain::TIP_OPTION, 'x' );
	$vault_dir = WP_CONTENT_DIR . '/uploads/wm-kanzlei/vault';
	@mkdir( $vault_dir, 0777, true );
	foreach ( [ '.htaccess', 'web.config', 'index.php', 'index.html' ] as $f ) {
		file_put_contents( $vault_dir . '/' . $f, 'x' );
	}
	define( 'WP_UNINSTALL_PLUGIN', 'wm-kanzlei-ai-sanitizer/wm-kanzlei-ai-sanitizer.php' );
	( static function (): void {
		include WM_KANZLEI_PATH . 'uninstall.php';
	} )();
	assert_test( 'uninstall preserves options and both tables by default when opt-in is off', is_array( get_option( 'wm_kanzlei_settings' ) ) && 'x' === get_option( AuditChain::TIP_OPTION ) && array_key_exists( 'wp_wm_kanzlei_sessions', $GLOBALS['wpdb']->tables ) && array_key_exists( 'wp_wm_kanzlei_audit_log', $GLOBALS['wpdb']->tables ) );

	update_option( Settings::DELETE_DATA_OPTION, '1' );
	( static function (): void {
		include WM_KANZLEI_PATH . 'uninstall.php';
	} )();
	assert_test( 'uninstall with opt-in deletes the settings, chain tip and opt-in flag', false === get_option( 'wm_kanzlei_settings' ) && false === get_option( AuditChain::TIP_OPTION ) && false === get_option( Settings::DELETE_DATA_OPTION ) );
	assert_test( 'uninstall with opt-in removes the vault directory of earlier versions', ! is_dir( $vault_dir ) );
	assert_test( 'uninstall with opt-in drops both tables through prepared identifiers', ! array_key_exists( 'wp_wm_kanzlei_sessions', $GLOBALS['wpdb']->tables ) && ! array_key_exists( 'wp_wm_kanzlei_audit_log', $GLOBALS['wpdb']->tables ) );
	@rmdir( WP_CONTENT_DIR . '/uploads' );
	@rmdir( WP_CONTENT_DIR );

	// ------------------------------------------------------------------------------------------------------------------
	echo "\n[TEST GROUP 12] Claims in docs and code\n";
	$docs = [];
	foreach ( [ 'README.md', 'README.de.md', 'README.es.md', 'readme.txt', 'DEVELOPERS.md', 'docs/ARCHITECTURE.md', 'docs/LEGAL-COMPLIANCE.md', 'llms.txt', 'public/humans.txt', 'wm-kanzlei-ai-sanitizer.php' ] as $doc ) {
		$docs[ $doc ] = is_file( WM_KANZLEI_PATH . $doc ) ? (string) file_get_contents( WM_KANZLEI_PATH . $doc ) : '';
	}
	foreach ( [ '/compliant/i' => 'compliant', '/zero[- ]knowledge/i' => 'zero-knowledge', '/merkle/i' => 'Merkle', '/surrogate vault/i' => 'surrogate vault', '/Founder & CEO/' => 'Founder & CEO', '/Zero[- ]PII/i' => 'Zero-PII' ] as $pattern => $label ) {
		// Quoted phrases ("…", „…“, «…») cite a claim, and lines about what an earlier version said record history.
		$claims_only = static fn( string $s ): string => (string) preg_replace( [ '/"[^"\n]*"|„[^“\n]*“|«[^»\n]*»/u', '/^.*\b(Until|Bis|Hasta)\b.*$/mu' ], '', $s );
		$hits        = array_keys( array_filter( $docs, static fn( string $s ): bool => 1 === preg_match( $pattern, $claims_only( $s ) ) ) );
		assert_test( "no \"{$label}\" claim in the docs", [] === $hits, implode( ', ', $hits ) );
	}
	assert_test( 'every document exists', ! in_array( '', $docs, true ), implode( ', ', array_keys( $docs, '', true ) ) );

	echo "\n==============================================================================\n";
	echo "  TEST SUITE RESULTS: {$passed_count} PASSED | {$failed_count} FAILED\n";
	echo "==============================================================================\n\n";

	exit( 0 === $failed_count ? 0 : 1 );
}
