<?php
/**
 * Which value types are replaced. Stored in the option `wm_kanzlei_settings`.
 *
 * Until 2026-09-15 the settings form wrote this option and nothing read it: unticking IBAN changed nothing, the
 * provider and retention fields described storage and dispatch that do not exist, and every save reset an
 * `alert_email` the form did not contain. Now the switches decide what REST, WP-CLI and the simulator replace;
 * a missing option or a missing key means "replace" (the protective default), and a save keeps keys it does not
 * show.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings {

	public const OPTION = 'wm_kanzlei_settings';

	public const DELETE_DATA_OPTION = 'wm_kanzlei_delete_data_on_uninstall';

	/** Setting key => entity type of NerEngine. */
	public const SWITCHES = [
		'redact_names'   => 'PERSON_NAME',
		'redact_iban'    => 'IBAN',
		'redact_tax'     => 'STEUER_ID',
		'redact_az'      => 'AKTENZEICHEN',
		'redact_amounts' => 'GELDBETRAG',
		'redact_phones'  => 'PHONE',
		'redact_email'   => 'EMAIL',
	];

	/** @return array<string, bool> Every switch, true unless stored as false. */
	public static function switches(): array {
		$stored = get_option( self::OPTION, [] );
		$stored = is_array( $stored ) ? $stored : [];
		$out    = [];
		foreach ( array_keys( self::SWITCHES ) as $key ) {
			$out[ $key ] = array_key_exists( $key, $stored ) ? (bool) $stored[ $key ] : true;
		}
		return $out;
	}

	/** @return list<string> Entity types to replace. */
	public static function enabled_types(): array {
		$types = [];
		foreach ( self::switches() as $key => $on ) {
			if ( $on ) {
				$types[] = self::SWITCHES[ $key ];
			}
		}
		return $types;
	}

	/**
	 * Store the switches from a submitted form; keys the form does not carry are kept as stored.
	 *
	 * @param array<string, mixed> $posted
	 */
	public static function save_switches( array $posted ): void {
		$stored = get_option( self::OPTION, [] );
		$stored = is_array( $stored ) ? $stored : [];
		foreach ( array_keys( self::SWITCHES ) as $key ) {
			$stored[ $key ] = ! empty( $posted[ $key ] );
		}
		update_option( self::OPTION, $stored, false );
	}

	/** Every switch on; other stored keys are kept. */
	public static function enable_all(): void {
		self::save_switches( array_fill_keys( array_keys( self::SWITCHES ), '1' ) );
	}

	/** Whether full data and table removal on uninstall has been explicitly opted into (default false). */
	public static function delete_data_on_uninstall(): bool {
		return filter_var( get_option( 'wm_kanzlei_delete_data_on_uninstall', '0' ), FILTER_VALIDATE_BOOLEAN );
	}

	/** Persist the explicit opt-in flag for removing options and tables on uninstall. */
	public static function save_delete_data_on_uninstall( bool $enabled ): void {
		update_option( 'wm_kanzlei_delete_data_on_uninstall', $enabled ? '1' : '0', false );
	}
}
