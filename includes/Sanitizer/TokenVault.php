<?php
/**
 * Replaces detected values with placeholders and puts them back.
 *
 * It keeps nothing: the placeholder-to-value mapping is returned to the caller, who has to send it back to
 * rehydrate. The result is pseudonymised text (DSGVO Art. 4 Nr. 5): whoever holds the mapping restores the values.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Sanitizer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TokenVault {

	/** A placeholder as the vault writes it: `{{TYPE_<16 hex>}}`. */
	public const PLACEHOLDER_PATTERN = '/^\{\{[A-Z_]+_[0-9a-f]{16,64}\}\}$/';

	/**
	 * Replace entities with placeholders derived from an HMAC of the value.
	 *
	 * 16 hex characters (64 bits); until 2026-09-15 it was 8 (32 bits), and two values of one type could share a
	 * placeholder and come back as the same value. A collision inside one text is also checked: the placeholder
	 * grows until it is unique.
	 *
	 * @param string                                                                   $text
	 * @param array<int, array{type: string, value: string, start: int, length: int}> $entities
	 * @param string                                                                   $salt Secret salt, random per call.
	 * @return array{sanitized_text: string, mapping: array<string, string>}
	 */
	public function tokenize( string $text, array $entities, string $salt ): array {
		$mapping   = [];
		$by_value  = [];
		$sanitized = $text;

		// Longer values first, so "Herr Müller" is replaced before a bare "Müller".
		usort( $entities, static fn( $a, $b ) => strlen( $b['value'] ) <=> strlen( $a['value'] ) );

		foreach ( $entities as $entity ) {
			$val  = (string) $entity['value'];
			$type = (string) $entity['type'];
			if ( '' === $val || isset( $by_value[ $type . "\0" . $val ] ) ) {
				continue;
			}
			$digest = hash_hmac( 'sha256', $type . "\0" . $val, $salt );
			$length = 16;
			do {
				$placeholder = sprintf( '{{%s_%s}}', $type, substr( $digest, 0, $length ) );
				$length     += 8;
			} while ( isset( $mapping[ $placeholder ] ) && $mapping[ $placeholder ] !== $val && $length <= 64 );

			$mapping[ $placeholder ]             = $val;
			$by_value[ $type . "\0" . $val ]     = $placeholder;
			$sanitized                           = str_replace( $val, $placeholder, $sanitized );
		}

		return [
			'sanitized_text' => $sanitized,
			'mapping'        => $mapping,
		];
	}

	/**
	 * Whether a mapping has the shape tokenize() produces: placeholder keys, string values.
	 *
	 * @param mixed $mapping
	 */
	public static function is_valid_mapping( $mapping ): bool {
		if ( ! is_array( $mapping ) ) {
			return false;
		}
		foreach ( $mapping as $placeholder => $value ) {
			if ( ! is_string( $placeholder ) || 1 !== preg_match( self::PLACEHOLDER_PATTERN, $placeholder ) || ! is_string( $value ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Put the values back. Pairs that are not placeholder => string are skipped (until 2026-09-15 a numeric key or
	 * an array value was a TypeError, an HTTP 500 on the REST route).
	 *
	 * @param string $llm_response
	 * @param array  $mapping
	 * @return string
	 */
	public function rehydrate( string $llm_response, array $mapping ): string {
		$pairs = [];
		foreach ( $mapping as $placeholder => $value ) {
			if ( is_string( $placeholder ) && 1 === preg_match( self::PLACEHOLDER_PATTERN, $placeholder ) && is_string( $value ) ) {
				$pairs[ $placeholder ] = $value;
			}
		}
		return strtr( $llm_response, $pairs );
	}
}
