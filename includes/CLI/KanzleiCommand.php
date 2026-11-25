<?php
/**
 * WP-CLI: `wp kanzlei sanitize "<text>"`.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_CLI;
use WP_CLI_Command;
use WMCyber\Kanzlei\Core\Plugin;
use WMCyber\Kanzlei\Core\Settings;

final class KanzleiCommand extends WP_CLI_Command {
	public static function register(): void {
		WP_CLI::add_command( 'kanzlei', self::class );
	}

	/**
	 * Replace the detected values in a text with placeholders and print the result. Nothing is stored and nothing
	 * is sent anywhere; the switches of the settings screen decide which types are replaced.
	 *
	 * ## OPTIONS
	 *
	 * <text>
	 * : Text to sanitise.
	 *
	 * ## EXAMPLES
	 *
	 *     wp kanzlei sanitize "Der Kläger im Verfahren 12 O 45/23 fordert von DE89370400440532013000 Zahlung."
	 */
	public function sanitize( array $args, array $assoc_args ): void {
		try {
			$report = self::report( (string) ( $args[0] ?? '' ) );
		} catch ( \InvalidArgumentException $e ) {
			WP_CLI::error( $e->getMessage() );
			return;
		}

		foreach ( $report['lines'] as $line ) {
			WP_CLI::line( $line );
		}
		if ( 0 === $report['count'] ) {
			WP_CLI::warning( 'No value of the checked types was found; the text above is unchanged.' );
			return;
		}
		WP_CLI::success( sprintf( '%d value(s) replaced. Check the text for what the patterns do not cover (see README).', $report['count'] ) );
	}

	/**
	 * The output of `sanitize` without WP_CLI, so the standalone suite can run it.
	 *
	 * Until 2026-09-15 the command used a fixed salt (the same placeholder on every run), documented a
	 * `--rehydrate` option it never read, printed every raw value to the terminal and ended with "PII successfully
	 * redacted and vaulted locally" even when nothing was found. Values are now shown masked.
	 *
	 * @return array{count: int, lines: list<string>, sanitized: string}
	 * @throws \InvalidArgumentException When the text is not valid UTF-8.
	 */
	public static function report( string $text ): array {
		$types     = Settings::enabled_types();
		$entities  = Plugin::instance()->get_ner_engine()->detect_entities( $text, $types );
		$tokenized = Plugin::instance()->get_token_vault()->tokenize( $text, $entities, bin2hex( random_bytes( 16 ) ) );

		$lines   = [ '=== WM Kanzlei AI Sanitizer ===', 'Checked types: ' . implode( ', ', $types ), sprintf( 'Values replaced: %d', count( $entities ) ) ];
		foreach ( $entities as $e ) {
			$lines[] = sprintf( '  - [%s] %s', $e['type'], self::mask( (string) $e['value'] ) );
		}
		$lines[] = '---------------------------------------------------------';
		$lines[] = 'Sanitised text:';
		$lines[] = $tokenized['sanitized_text'];

		return [ 'count' => count( $entities ), 'lines' => $lines, 'sanitized' => $tokenized['sanitized_text'] ];
	}

	/** First two characters and the length: enough to recognise a value, not to read it from a log. */
	public static function mask( string $value ): string {
		return mb_substr( $value, 0, 2 ) . str_repeat( '*', max( 0, mb_strlen( $value ) - 2 ) );
	}
}
