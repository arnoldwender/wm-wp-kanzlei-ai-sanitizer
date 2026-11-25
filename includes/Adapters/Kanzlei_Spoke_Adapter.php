<?php
/**
 * WM Suite Kanzlei AI Sanitizer — Suite Hub Spoke Adapter
 *
 * Health from the tables, the audit chain and a detection self-test; telemetry from the tables; one SBOM
 * component (a fragment the hub places in its document).
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Adapters;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! interface_exists( 'ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface' ) ) {
	return;
}

use ArnoldWender\SuiteHub\Contracts\WM_Plugin_Module_Interface;
use WMCyber\Kanzlei\Audit\AuditChain;
use WMCyber\Kanzlei\Sanitizer\NerEngine;

final class Kanzlei_Spoke_Adapter implements WM_Plugin_Module_Interface {

	/** Sample for the self-test and the values it must find. */
	private const SAMPLE = 'Im Verfahren 12 O 45/23 überweisen Sie an DE89370400440532013000 oder per Mail an test@kanzlei-muster.de; Frau Dr. Schneider erhält 15.000 €.';

	private const SAMPLE_TYPES = [ 'AKTENZEICHEN', 'IBAN', 'EMAIL', 'PERSON_NAME', 'GELDBETRAG' ];

	/** @var (callable(string): array)|null Replaces the detector in the self-test; the hub constructs without it. */
	private $detector;

	public function __construct( ?callable $detector = null ) {
		$this->detector = $detector;
	}

	public function get_module_slug(): string {
		return 'wm-kanzlei-ai-sanitizer';
	}

	public function get_name(): string {
		return 'WM Kanzlei AI Sanitizer';
	}

	public function get_version(): string {
		return defined( 'WM_KANZLEI_VERSION' ) ? WM_KANZLEI_VERSION : '1.2.2';
	}

	public function get_description(): string {
		return 'Ersetzt Aktenzeichen, IBAN, E-Mail, Steuer-ID, Telefonnummern, Namen nach einer Anrede und Geldbeträge durch Platzhalter und setzt sie wieder ein; protokolliert die Aufrufe in einer HMAC-Kette.';
	}

	/**
	 * `ERROR` without the tables or with a broken chain or a failing self-test, `HEALTHY` otherwise. Until
	 * 2026-09-15 the literal `HEALTHY`.
	 */
	public function get_health_status(): string {
		if ( ! $this->tables_present() || 'BROKEN' === AuditChain::verify()['status'] || ! $this->self_test()['success'] ) {
			return 'ERROR';
		}
		return 'HEALTHY';
	}

	public function get_sbom_data(): array {
		return [
			'bom-ref'     => 'pkg:wordpress/wm-kanzlei-ai-sanitizer@' . $this->get_version(),
			'type'        => 'application',
			'name'        => $this->get_name(),
			'version'     => $this->get_version(),
			'description' => $this->get_description(),
			'scope'       => 'required',
			'hashes'      => [
				[
					'alg'     => 'SHA-256',
					'content' => hash_file( 'sha256', WM_KANZLEI_FILE ),
				],
			],
			'licenses'    => [
				[
					'license' => [
						'id' => 'GPL-2.0-or-later',
					],
				],
			],
			// Until 2026-09-15 three properties named § 203 StGB, § 43e BRAO and DSGVO Art. 5 as "compliance".
			'properties'  => [
				[
					'name'  => 'wm:features:detected-types',
					'value' => implode( ', ', NerEngine::TYPES ),
				],
				[
					'name'  => 'wm:features:outbound-requests',
					'value' => 'none',
				],
			],
		];
	}

	public function get_dependencies(): array {
		return [];
	}

	/** Until 2026-09-15 `page=wm-kanzlei-dashboard`, a page that does not exist. */
	public function get_settings_url(): ?string {
		return admin_url( 'admin.php?page=wm-kanzlei-sanitizer&tab=settings' );
	}

	public function get_telemetry_metrics(): array {
		global $wpdb;
		$total_sessions = 0;
		$total_redacted = 0;
		$audit_records  = 0;
		if ( $this->tables_present() ) {
			$sessions = $wpdb->prefix . 'wm_kanzlei_sessions';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$total_sessions = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $sessions ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$total_redacted = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(SUM(entities_redacted), 0) FROM %i', $sessions ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$audit_records = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', AuditChain::table() ) );
		}
		$chain = AuditChain::verify();

		return [
			'total_sessions'          => $total_sessions,
			'total_entities_redacted' => $total_redacted,
			'audit_records'           => $audit_records,
			'audit_chain_status'      => $chain['status'],
			'audit_rows_unchained'    => $chain['unchained'],
			'detection_self_test'     => $this->self_test()['success'] ? 'PASS' : 'FAIL',
			'mapping_storage'         => 'returned_to_caller',
			'outbound_requests'       => 0,
		];
	}

	public function execute_action( string $action, array $params = [] ): array {
		switch ( $action ) {
			case 'self_test':
				return $this->self_test();

			case 'verify_chain':
				$chain = AuditChain::verify();
				return [
					'success' => in_array( $chain['status'], [ 'INTACT', 'EMPTY_CHAIN' ], true ),
					'message' => sprintf( 'Audit-Kette: %s, %d versiegelte Zeilen, %d Zeilen vor der Kette%s.', $chain['status'], $chain['checked'], $chain['unchained'], null !== $chain['error'] ? ' (' . $chain['error'] . ')' : '' ),
				];

			default:
				// Plain text: the hub escapes where it renders.
				return [
					'success' => false,
					'message' => sprintf( 'Unbekannte Spoke-Aktion "%s".', $action ),
				];
		}
	}

	/**
	 * Detection against a fixed sample; the message says what was found and what was missing. Until 2026-09-15
	 * it said "NER-Test erfolgreich … (Aktenzeichen, IBAN, E-Mail)" whatever the result was.
	 *
	 * @return array{success: bool, message: string}
	 */
	private function self_test(): array {
		try {
			$entities = null !== $this->detector ? ( $this->detector )( self::SAMPLE ) : ( new NerEngine() )->detect_entities( self::SAMPLE );
			$found    = array_values( array_unique( array_column( $entities, 'type' ) ) );
		} catch ( \Throwable $e ) {
			return [ 'success' => false, 'message' => 'Erkennungstest fehlgeschlagen: ' . $e->getMessage() ];
		}
		$missing = array_values( array_diff( self::SAMPLE_TYPES, $found ) );
		return [
			'success' => [] === $missing,
			'message' => [] === $missing
				? sprintf( 'Erkennungstest bestanden: %s im Testtext gefunden.', implode( ', ', $found ) )
				: sprintf( 'Erkennungstest fehlgeschlagen: %s nicht gefunden (gefunden: %s).', implode( ', ', $missing ), $found ? implode( ', ', $found ) : 'nichts' ),
		];
	}

	private function tables_present(): bool {
		global $wpdb;
		$sessions = $wpdb->prefix . 'wm_kanzlei_sessions';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return AuditChain::table_present() && $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $sessions ) ) ) === $sessions;
	}
}
