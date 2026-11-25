<?php
/**
 * REST routes under wm-kanzlei/v1.
 *
 * /sanitize and /rehydrate do the work; /audit-log and /certificate read what was recorded; /proxy forwards
 * nothing and says so. No route sends text to an AI provider: the plugin makes no outbound request.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\API;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\Kanzlei\Audit\AuditChain;
use WMCyber\Kanzlei\Core\Settings;
use WMCyber\Kanzlei\Sanitizer\NerEngine;
use WMCyber\Kanzlei\Sanitizer\TokenVault;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

final class RestController {
	private const REST_NAMESPACE = 'wm-kanzlei/v1';

	public function __construct(
		private readonly NerEngine $ner_engine,
		private readonly TokenVault $token_vault
	) {}

	public function register_routes(): void {
		add_action( 'rest_api_init', [ $this, 'register' ] );
	}

	public function register(): void {
		register_rest_route( self::REST_NAMESPACE, '/sanitize', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'sanitize_prompt' ],
			'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
			'args'                => [
				'prompt' => [ 'type' => 'string', 'required' => true ],
			],
		] );

		register_rest_route( self::REST_NAMESPACE, '/rehydrate', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rehydrate_response' ],
			'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
			'args'                => [
				'response' => [ 'type' => 'string', 'required' => true ],
				'mapping'  => [ 'required' => true ],
			],
		] );

		// Until 2026-09-15 this answered with a fixed German legal opinion ("die geltend gemachten Ansprüche
		// vollumfänglich begründet … unverzüglich Klage einzureichen") wrapped around the prompt, plus
		// "stgb_203_certified": true. No provider was ever called.
		register_rest_route( self::REST_NAMESPACE, '/proxy', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'proxy_not_available' ],
			'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
		] );

		register_rest_route( self::REST_NAMESPACE, '/audit-log', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'get_audit_log' ],
			'permission_callback' => static fn() => current_user_can( 'manage_options' ),
		] );

		// Until 2026-09-15 this issued a "§ 203 StGB & § 43e BRAO" certificate for any session id, including ones
		// that never existed, with a hash anyone could recompute from the source. It now returns what the database
		// holds about one session, or 404.
		register_rest_route( self::REST_NAMESPACE, '/certificate', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'get_session_record' ],
			'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
			'args'                => [
				'session_id' => [ 'type' => 'string', 'required' => true ],
			],
		] );
	}

	public function sanitize_prompt( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$prompt = $request->get_param( 'prompt' );
		// '' only: until 2026-09-15 empty() also refused the prompt "0".
		if ( ! is_string( $prompt ) || '' === $prompt ) {
			return new WP_Error( 'empty_prompt', 'Prompt text cannot be empty', [ 'status' => 400 ] );
		}

		$types = Settings::enabled_types();
		try {
			$entities = $this->ner_engine->detect_entities( $prompt, $types );
		} catch ( \InvalidArgumentException $e ) {
			return new WP_Error( 'wm_kanzlei_invalid_encoding', $e->getMessage(), [ 'status' => 400 ] );
		} catch ( \RuntimeException $e ) {
			return new WP_Error( 'wm_kanzlei_detection_failed', 'Detection failed; nothing was replaced.', [ 'status' => 500 ] );
		}

		$session_id = bin2hex( random_bytes( 16 ) );
		$tokenized  = $this->token_vault->tokenize( $prompt, $entities, bin2hex( random_bytes( 16 ) ) );
		$found      = array_values( array_unique( array_column( $entities, 'type' ) ) );
		$now        = current_time( 'mysql', true );

		global $wpdb;
		$sessions = $wpdb->prefix . 'wm_kanzlei_sessions';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$stored = $wpdb->insert(
			$sessions,
			[
				'session_id'        => $session_id,
				'operator_id'       => get_current_user_id(),
				'entities_redacted' => count( $entities ),
				'prompt_tokens_est' => (int) ( strlen( $prompt ) / 4 ),
				'created_at'        => $now,
			],
			[ '%s', '%d', '%d', '%d', '%s' ]
		);
		if ( false === $stored ) {
			return new WP_Error( 'wm_kanzlei_audit_unavailable', 'The session could not be recorded; nothing is returned.', [ 'status' => 503 ] );
		}

		$audit = AuditChain::append( $session_id, 'PROMPT_SANITIZATION', $found ? implode( ', ', $found ) : 'NONE', $now );
		if ( ! $audit['ok'] ) {
			// The session row without its audit row would be a record of something the log does not show.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->delete( $sessions, [ 'session_id' => $session_id ], [ '%s' ] );
			return new WP_Error( 'wm_kanzlei_audit_unavailable', 'The audit row could not be written (' . $audit['error'] . '); nothing is returned.', [ 'status' => 503 ] );
		}

		$warnings = $this->ner_engine->collect_review_warnings( $prompt, $entities );

		$payload = [
			'success'         => true,
			'session_id'      => $session_id,
			'sanitized_text'  => $tokenized['sanitized_text'],
			'entities_found'  => count( $entities ),
			'entity_types'    => $found,
			'types_checked'   => $types,
			'mapping'         => $tokenized['mapping'],
			'review_warnings' => $warnings,
			'audit_id'        => $audit['id'],
		];

		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filters the REST `/sanitize` response payload after the session and audit rows are sealed.
			 *
			 * @param array<string, mixed> $payload    Response data array.
			 * @param string               $session_id Generated session identifier.
			 * @param list<string>         $found      Detected entity type codes.
			 */
			$filtered = apply_filters( 'wm_kanzlei_sanitized_result', $payload, $session_id, $found );
			if ( is_array( $filtered ) ) {
				$payload = $filtered;
			}
		}

		return new WP_REST_Response( $payload );
	}

	public function rehydrate_response( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$response = $request->get_param( 'response' );
		$mapping  = $request->get_param( 'mapping' );

		if ( ! is_string( $response ) || '' === $response ) {
			return new WP_Error( 'empty_response', 'LLM Response text cannot be empty', [ 'status' => 400 ] );
		}
		// Until 2026-09-15 a mapping with a numeric key or a non-string value was a TypeError (HTTP 500).
		if ( ! TokenVault::is_valid_mapping( $mapping ) ) {
			return new WP_Error( 'wm_kanzlei_invalid_mapping', 'mapping must be an object of placeholders ({{TYPE_hex}}) to strings, as /sanitize returns it.', [ 'status' => 400 ] );
		}

		return new WP_REST_Response( [
			'success'         => true,
			'rehydrated_text' => $this->token_vault->rehydrate( $response, $mapping ),
		] );
	}

	public function proxy_not_available( WP_REST_Request $request ): WP_Error {
		return new WP_Error(
			'wm_kanzlei_no_provider',
			'No AI provider is connected: this route forwards nothing and returns no completion. Use /sanitize, send the text yourself, then /rehydrate.',
			[ 'status' => 501 ]
		);
	}

	public function get_audit_log( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;
		$rows  = [];
		$total = 0;
		if ( AuditChain::table_present() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, session_id, action, entity_types_summary, previous_hash, current_hash, created_at FROM %i ORDER BY id DESC LIMIT 50', AuditChain::table() ), ARRAY_A );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', AuditChain::table() ) );
		}

		return new WP_REST_Response( [
			'success' => true,
			'total'   => $total,
			'logs'    => $rows ?: [],
			'chain'   => AuditChain::verify(),
		] );
	}

	public function get_session_record( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;
		$session_id = (string) $request->get_param( 'session_id' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$session = $wpdb->get_row( $wpdb->prepare( 'SELECT session_id, operator_id, entities_redacted, created_at FROM %i WHERE session_id = %s', $wpdb->prefix . 'wm_kanzlei_sessions', $session_id ), ARRAY_A );
		if ( ! $session ) {
			return new WP_Error( 'wm_kanzlei_unknown_session', 'No such session.', [ 'status' => 404 ] );
		}
		if ( ! current_user_can( 'manage_options' ) && (int) $session['operator_id'] !== get_current_user_id() ) {
			return new WP_Error( 'wm_kanzlei_forbidden', 'Only administrators and the user who ran the session can read its record.', [ 'status' => 403 ] );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$audit = $wpdb->get_row( $wpdb->prepare( 'SELECT id, action, entity_types_summary, previous_hash, current_hash FROM %i WHERE session_id = %s ORDER BY id ASC LIMIT 1', AuditChain::table(), $session_id ), ARRAY_A );
		$chain = AuditChain::verify();

		return new WP_REST_Response( [
			'success'           => true,
			'record_type'       => 'session_record',
			'session_id'        => $session['session_id'],
			'created_at_utc'    => $session['created_at'],
			'operator_id'       => (int) $session['operator_id'],
			'entities_redacted' => (int) $session['entities_redacted'],
			'audit'             => $audit ? [
				'id'           => (int) $audit['id'],
				'action'       => $audit['action'],
				'entity_types' => $audit['entity_types_summary'],
				'seal'         => $audit['current_hash'],
				'sealed'       => '' !== (string) $audit['previous_hash'],
			] : null,
			'chain_status'      => $chain['status'],
			'note'              => 'A record of what the plugin replaced in one text. It is not a certificate of conformity with § 203 StGB, § 43e BRAO or the DSGVO, and it does not show what was sent anywhere.',
		] );
	}
}
