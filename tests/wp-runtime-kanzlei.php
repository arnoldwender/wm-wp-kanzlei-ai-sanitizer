<?php
/**
 * Runtime check of wm-kanzlei-ai-sanitizer inside a real WordPress, rolled back.
 *
 * It calls the REST routes through rest_do_request() (so core's argument validation and permission callbacks run),
 * a real /sanitize with its session and sealed audit row, the chain verification, the settings switches, the hub
 * adapter and the admin screen. Everything runs inside a transaction that is rolled back when PHP shuts down:
 * transaction statements of other plugins become savepoints, DDL is refused, a persistent object cache is refused.
 * After the rollback the table counts and the tip option are read again with SQL and compared with the values from
 * before; a difference exits 1. GET_LOCK and auto-increment counters are not transactional.
 *
 *   wp eval-file wp-content/plugins/wm-kanzlei-ai-sanitizer/tests/wp-runtime-kanzlei.php --user=1
 *   ssh <box> 'wp --path=<www> eval-file - --user=1' < tests/wp-runtime-kanzlei.php
 *
 * `wp eval-file` runs the file inside a method: state lives in $GLOBALS.
 *
 * @package WMCyber\Kanzlei
 */

defined( 'ABSPATH' ) || exit;

if ( wp_using_ext_object_cache() ) {
	WP_CLI::error( 'A persistent object cache is active; the rollback would leave cached options behind. Not run.' );
}
if ( ! class_exists( 'WMCyber\Kanzlei\Audit\AuditChain' ) ) {
	WP_CLI::error( 'wm-kanzlei-ai-sanitizer (with AuditChain) is not loaded.' );
}

global $wpdb;
$GLOBALS['kzrt'] = [ 'pass' => 0, 'fail' => 0 ];
$GLOBALS['kzrt_check'] = static function ( bool $ok, string $label ): void {
	$GLOBALS['kzrt'][ $ok ? 'pass' : 'fail' ]++;
	echo ( $ok ? '  [PASS] ' : '  [FAIL] ' ) . $label . "\n";
};
$GLOBALS['kzrt_state'] = static function (): array {
	global $wpdb;
	$s = $wpdb->prefix . 'wm_kanzlei_sessions';
	$a = $wpdb->prefix . 'wm_kanzlei_audit_log';
	// phpcs:disable WordPress.DB.DirectDatabaseQuery
	return [
		'sessions' => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $s ) ),
		'audit'    => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $a ) ),
		'tip'      => (string) $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, 'wm_kanzlei_audit_chain_tip' ) ),
		'settings' => (string) $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, 'wm_kanzlei_settings' ) ),
	];
	// phpcs:enable
};
$GLOBALS['kzrt_before'] = $GLOBALS['kzrt_state']();

// --- Transaction with savepoint rewrite ----------------------------------------------------------------------------
$GLOBALS['kzrt_depth'] = 0;
$GLOBALS['kzrt_rewrite'] = static function ( $query ) {
	$q = ltrim( (string) $query );
	if ( preg_match( '/^(START\s+TRANSACTION|BEGIN)\b/i', $q ) ) {
		++$GLOBALS['kzrt_depth'];
		return 'SAVEPOINT kzrt_' . $GLOBALS['kzrt_depth'];
	}
	if ( preg_match( '/^COMMIT\b/i', $q ) ) {
		return $GLOBALS['kzrt_depth'] > 0 ? 'RELEASE SAVEPOINT kzrt_' . $GLOBALS['kzrt_depth']-- : 'SELECT 1';
	}
	if ( preg_match( '/^ROLLBACK\b/i', $q ) ) {
		return $GLOBALS['kzrt_depth'] > 0 ? 'ROLLBACK TO SAVEPOINT kzrt_' . $GLOBALS['kzrt_depth']-- : 'SELECT 1';
	}
	return preg_match( '/^(ALTER|CREATE|DROP|TRUNCATE|RENAME|LOCK\s+TABLES|UNLOCK\s+TABLES|SET\s+autocommit)\b/i', $q ) ? '' : $query;
};
$wpdb->query( 'START TRANSACTION' );
add_filter( 'query', $GLOBALS['kzrt_rewrite'] );
register_shutdown_function(
	static function (): void {
		global $wpdb;
		remove_filter( 'query', $GLOBALS['kzrt_rewrite'] );
		$wpdb->query( 'ROLLBACK' );
		$after = $GLOBALS['kzrt_state']();
		$same  = $after === $GLOBALS['kzrt_before'];
		echo "\n  ROLLBACK CHECK: " . ( $same ? 'sessions, audit rows, tip and settings equal to before' : 'DIFFERENT ' . wp_json_encode( [ 'before' => $GLOBALS['kzrt_before'], 'after' => $after ] ) ) . "\n";
		echo "  RUNTIME RESULTS: {$GLOBALS['kzrt']['pass']} PASSED | {$GLOBALS['kzrt']['fail']} FAILED\n";
		exit( $same && 0 === $GLOBALS['kzrt']['fail'] ? 0 : 1 );
	}
);

$check = $GLOBALS['kzrt_check'];
$call  = static function ( string $method, string $route, array $params = [] ): WP_REST_Response {
	$request = new WP_REST_Request( $method, $route );
	if ( 'GET' === $method ) {
		$request->set_query_params( $params );
	} else {
		$request->set_header( 'content-type', 'application/json' );
		$request->set_body( (string) wp_json_encode( $params ) );
	}
	return rest_ensure_response( rest_do_request( $request ) );
};

echo "\n=== WM KANZLEI AI SANITIZER · RUNTIME (rolled back) ===\n";
echo '  [INFO] before: ' . wp_json_encode( [ 'sessions' => $GLOBALS['kzrt_before']['sessions'], 'audit' => $GLOBALS['kzrt_before']['audit'], 'tip' => '' !== $GLOBALS['kzrt_before']['tip'] ] ) . "\n";

$routes = rest_get_server()->get_routes();
$check( isset( $routes['/wm-kanzlei/v1/sanitize'], $routes['/wm-kanzlei/v1/rehydrate'], $routes['/wm-kanzlei/v1/proxy'], $routes['/wm-kanzlei/v1/audit-log'], $routes['/wm-kanzlei/v1/certificate'] ), 'five routes registered' );

$r = $call( 'POST', '/wm-kanzlei/v1/proxy', [ 'prompt' => 'Bitte prüfen: Herrn Müller wurde gekündigt.' ] );
$check( 501 === $r->get_status() && 'wm_kanzlei_no_provider' === ( $r->get_data()['code'] ?? '' ), '/proxy -> 501 wm_kanzlei_no_provider (was a fixed legal opinion with stgb_203_certified)' );

$r = $call( 'GET', '/wm-kanzlei/v1/certificate', [ 'session_id' => 'never-existed-123' ] );
$check( 404 === $r->get_status(), '/certificate for an unknown session -> 404 (was a certificate)' );

$r = $call( 'POST', '/wm-kanzlei/v1/rehydrate', [ 'response' => 'x', 'mapping' => [ 'a', 'b' ] ] );
$check( 400 === $r->get_status(), '/rehydrate with a list as mapping -> 400 (was a TypeError, HTTP 500)' );

$r = $call( 'POST', '/wm-kanzlei/v1/sanitize', [] );
$check( 400 === $r->get_status(), '/sanitize without prompt -> 400 (core validates the declared argument)' );

$text = 'In Sachen Müller, Az. VI ZR 244/20, zahlt Herrn Jonas Müller 50.000,00 € an DE89 3704 0044 0532 0130 00; Tel. +49 345 1234567.';
$r    = $call( 'POST', '/wm-kanzlei/v1/sanitize', [ 'prompt' => $text ] );
$data = $r->get_data();
$out  = (string) ( $data['sanitized_text'] ?? '' );
$check( 200 === $r->get_status() && ! str_contains( $out, 'Müller' ) && ! str_contains( $out, 'VI ZR' ) && ! str_contains( $out, '50.000' ) && ! str_contains( $out, 'DE89' ) && ! str_contains( $out, '+49' ), '/sanitize replaces file number, names, amount with €, spaced IBAN and +49 phone: ' . $out );
$check( preg_match_all( '/\{\{[A-Z_]+_[0-9a-f]{16}\}\}/', $out ) >= 5, 'placeholders carry 16 hex characters' );
$check( ! empty( $data['audit_id'] ), '/sanitize returns an audit id' );

$chain = WMCyber\Kanzlei\Audit\AuditChain::verify();
$check( 'INTACT' === $chain['status'] && $chain['checked'] >= 1, 'chain after the call: ' . $chain['status'] . ', ' . $chain['checked'] . ' sealed, ' . $chain['unchained'] . ' before the chain' );

$r = $call( 'GET', '/wm-kanzlei/v1/certificate', [ 'session_id' => (string) ( $data['session_id'] ?? '' ) ] );
$check( 200 === $r->get_status() && 'session_record' === ( $r->get_data()['record_type'] ?? '' ) && ! isset( $r->get_data()['standard'] ), '/certificate for the real session -> its record, no statute' );

$r = $call( 'POST', '/wm-kanzlei/v1/rehydrate', [ 'response' => 'Antwort: ' . $out, 'mapping' => $data['mapping'] ?? [] ] );
$check( 200 === $r->get_status() && 'Antwort: ' . $text === ( $r->get_data()['rehydrated_text'] ?? '' ), '/rehydrate restores the original text' );

$r = $call( 'GET', '/wm-kanzlei/v1/audit-log' );
$check( 200 === $r->get_status() && 'INTACT' === ( $r->get_data()['chain']['status'] ?? '' ), '/audit-log returns the chain result' );

$bad_utf8 = new WP_REST_Request( 'POST', '/wm-kanzlei/v1/sanitize' );
$bad_utf8->set_body_params( [ 'prompt' => "Herr Müller Gr\xFC\xDFe" ] );
$r = rest_ensure_response( rest_do_request( $bad_utf8 ) );
$check( 400 === $r->get_status(), '/sanitize with invalid UTF-8 (form body) -> 400, nothing replaced' );

update_option( 'wm_kanzlei_settings', [ 'redact_iban' => false ], false );
$r = $call( 'POST', '/wm-kanzlei/v1/sanitize', [ 'prompt' => 'Herr Müller zahlt an DE89370400440532013000.' ] );
$check( str_contains( (string) ( $r->get_data()['sanitized_text'] ?? '' ), 'DE89370400440532013000' ) && ! str_contains( (string) ( $r->get_data()['sanitized_text'] ?? '' ), 'Müller' ), 'switching IBAN off leaves the IBAN in the text (settings were never read)' );

if ( class_exists( 'WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter' ) ) {
	$adapter = new WMCyber\Kanzlei\Adapters\Kanzlei_Spoke_Adapter();
	$check( 'HEALTHY' === $adapter->get_health_status() && true === $adapter->execute_action( 'self_test' )['success'], 'hub adapter: HEALTHY and self-test passes' );
	$check( str_contains( (string) $adapter->get_settings_url(), 'page=wm-kanzlei-sanitizer' ), 'hub settings link opens the plugin page' );
}

$GLOBALS['kzrt_warnings'] = [];
set_error_handler( static function ( $no, $msg, $file, $line ) { $GLOBALS['kzrt_warnings'][] = $msg . ' @ ' . basename( (string) $file ) . ':' . $line; return true; } );
$admin = new WMCyber\Kanzlei\Admin\AdminDashboard( WMCyber\Kanzlei\Core\Plugin::instance()->get_ner_engine(), WMCyber\Kanzlei\Core\Plugin::instance()->get_token_vault() );
$html  = '';
foreach ( [ 'overview', 'simulator', 'settings', 'log', 'help' ] as $tab ) {
	$_GET['tab'] = $tab;
	ob_start();
	$admin->render_dashboard_page();
	$html .= (string) ob_get_clean();
}
restore_error_handler();
$check( [] === $GLOBALS['kzrt_warnings'], 'admin tabs render without PHP notices' . ( $GLOBALS['kzrt_warnings'] ? ': ' . $GLOBALS['kzrt_warnings'][0] : '' ) );
$check( ! preg_match( '/COMPLIANT|CUSTODIA|ANONIMIZACI|100%/', $html ) && str_contains( $html, 'Nicht erkannt werden' ), 'admin screen without compliance claims, with the not-detected list' );
