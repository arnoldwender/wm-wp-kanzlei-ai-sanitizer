<?php
declare(strict_types=1);

namespace WMCyber\Kanzlei\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Looks for null bytes and stream wrappers (php://, file://, …) in GET, POST and cookie values and reports the
 * first one it finds. It does not block: the caller ignores the result and the request goes on. The report fires
 * the action `wm_sentinel_security_incident` and, when `WP_DEBUG` is enabled, writes a line to the PHP error log
 * without the client IP; until 2026-09-15 the log line carried the IP.
 */
final class RequestShield {
	private const DANGEROUS_PROTOCOLS = [
		'php://', 'data://', 'expect://', 'phar://', 'zip://', 'glob://', 'file://'
	];

	public static function inspect_globals(): bool {
		$sources = [ 'GET' => $_GET, 'POST' => $_POST, 'COOKIE' => $_COOKIE ];
		foreach ( $sources as $type => $data ) {
			if ( ! self::scan_array( $data, $type ) ) {
				return false;
			}
		}
		return true;
	}

	private static function scan_array( array $array, string $source_name ): bool {
		foreach ( $array as $key => $value ) {
			if ( is_array( $value ) ) {
				if ( ! self::scan_array( $value, $source_name ) ) {
					return false;
				}
				continue;
			}
			if ( is_string( $value ) && ! self::is_string_safe( (string) $key, $value, $source_name ) ) {
				return false;
			}
		}
		return true;
	}

	public static function is_string_safe( string $key, string $value, string $source = 'REQUEST' ): bool {
		if ( str_contains( $value, "\0" ) || str_contains( $value, '%00' ) ) {
			self::log_and_block( 'Null-byte injection detected', $key, $source );
			return false;
		}

		$lowered = strtolower( $value );
		foreach ( self::DANGEROUS_PROTOCOLS as $proto ) {
			if ( str_starts_with( $lowered, $proto ) || str_contains( $lowered, ' ' . $proto ) ) {
				self::log_and_block( 'Dangerous stream wrapper: ' . $proto, $key, $source );
				return false;
			}
		}

		return true;
	}

	private static function log_and_block( string $reason, string $param, string $source ): void {
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1' ) );
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- guarded by WP_DEBUG; do_action fires unconditionally below.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && function_exists( 'error_log' ) ) { error_log( sprintf( '[WM-KANZLEI-REQUEST-REPORT] %s in %s "%s" (not blocked)', $reason, $source, $param ) ); }
		do_action( 'wm_sentinel_security_incident', [
			'type'      => 'REQUEST_SHIELD_BLOCK',
			'reason'    => $reason,
			'parameter' => $param,
			'ip'        => $ip,
			'timestamp' => time(),
		] );
	}
}
