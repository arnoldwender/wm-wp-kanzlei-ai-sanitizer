<?php
/**
 * The audit log of sanitisation calls and the hash chain that links its rows.
 *
 * Until 2026-09-15 every row carried previous_hash = sha256('INIT') and current_hash = sha256(session_id .
 * created_at): no row referred to another and anyone could recompute a hash, while the docs called it a
 * "Merkle-hashed", "tamper-evident hash chain". What replaced it:
 *
 * - the seal is an HMAC keyed with wp_salt( 'secure_auth' ), which lives in wp-config.php, not in the database;
 * - every seal binds the previous row's seal and the row contents, so editing, deleting, inserting or reordering a
 *   row breaks verification from that row on;
 * - the newest seal is mirrored in an option, so removing the newest rows, or all of them, is caught while that
 *   option is left as it was; appends are serialised with a MySQL lock and nothing is appended without it.
 *
 * What it does NOT give: it is tamper-evident rather than write-once. Whoever holds wp-config.php can re-seal the chain;
 * whoever can write the database can set the tip option back to an older seal or delete the rows together with
 * the option. Rows written before the chain (empty previous_hash) are counted as unchained, not verified. A site
 * whose salts change (a copy of the database to another install) verifies as BROKEN from its first sealed row.
 * The log records that a sanitisation ran and which types were found; it does not record what was sent anywhere.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AuditChain {

	public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

	public const TIP_OPTION = 'wm_kanzlei_audit_chain_tip';

	private const SEAL_DOMAIN = 'WM-KANZLEI-AUDIT-V1';

	private const LOCK_NAME = 'wm_kanzlei_audit_chain';

	private const LOCK_TIMEOUT = 5;

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'wm_kanzlei_audit_log';
	}

	/** Digest of the fields a reader relies on. */
	public static function record_hash( string $session_id, string $action, string $types, string $created_at ): string {
		return hash( 'sha256', self::SEAL_DOMAIN . '|' . $session_id . '|' . $action . '|' . $types . '|' . $created_at );
	}

	public static function seal( string $previous, string $record_hash ): string {
		return hash_hmac( 'sha256', $previous . '|' . $record_hash, wp_salt( 'secure_auth' ) );
	}

	/**
	 * Append a row. Returns the row id and seal, or an error when nothing was written (lock not obtained, insert
	 * refused); the tip only moves after a successful insert.
	 *
	 * @return array{ok: bool, id?: int, seal?: string, error?: string}
	 */
	public static function append( string $session_id, string $action, string $types, string $created_at ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$locked = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK( %s, %d )', self::LOCK_NAME, self::LOCK_TIMEOUT ) );
		if ( '1' !== (string) $locked ) {
			return [ 'ok' => false, 'error' => 'the audit chain lock was not obtained' ];
		}

		try {
			$previous = self::chain_head();
			$seal     = self::seal( $previous, self::record_hash( $session_id, $action, $types, $created_at ) );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$inserted = $wpdb->insert(
				self::table(),
				[
					'session_id'           => $session_id,
					'action'               => $action,
					'entity_types_summary' => $types,
					// The column's name and default claim a standard; the plugin assesses none.
					'compliance_standard'  => 'NONE',
					'previous_hash'        => $previous,
					'current_hash'         => $seal,
					'created_at'           => $created_at,
				],
				[ '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
			);
			if ( false === $inserted ) {
				return [ 'ok' => false, 'error' => 'the audit row was refused by the database' ];
			}
			$id = (int) $wpdb->insert_id;

			update_option( self::TIP_OPTION, $seal, false );
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK( %s )', self::LOCK_NAME ) );
		}

		return [ 'ok' => true, 'id' => $id, 'seal' => $seal ];
	}

	/** The recorded tip, else the newest sealed row, else genesis. */
	private static function chain_head(): string {
		global $wpdb;
		$recorded = (string) get_option( self::TIP_OPTION, '' );
		if ( '' !== $recorded ) {
			return $recorded;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$tip = $wpdb->get_var( $wpdb->prepare( "SELECT current_hash FROM %i WHERE previous_hash <> '' ORDER BY id DESC LIMIT 1", self::table() ) );
		return $tip ? (string) $tip : self::GENESIS_HASH;
	}

	public static function table_present(): bool {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	/**
	 * Walk the rows in id order.
	 *
	 * @return array{status: string, checked: int, unchained: int, broken_id: ?int, error: ?string}
	 */
	public static function verify(): array {
		global $wpdb;
		$result = [ 'status' => 'INTACT', 'checked' => 0, 'unchained' => 0, 'broken_id' => null, 'error' => null ];

		if ( ! self::table_present() ) {
			return [ 'status' => 'BROKEN', 'error' => 'the audit table is missing' ] + $result;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows       = $wpdb->get_results( $wpdb->prepare( 'SELECT id, session_id, action, entity_types_summary, previous_hash, current_hash, created_at FROM %i ORDER BY id ASC', self::table() ), ARRAY_A );
		$stored_tip = (string) get_option( self::TIP_OPTION, '' );

		if ( empty( $rows ) ) {
			if ( '' !== $stored_tip ) {
				return [ 'status' => 'BROKEN', 'error' => 'no audit rows, but a chain tip is recorded (the rows were removed)' ] + $result;
			}
			return [ 'status' => 'EMPTY_CHAIN' ] + $result;
		}

		$expected_prev = self::GENESIS_HASH;
		$seen_sealed   = false;
		foreach ( $rows as $row ) {
			$id = (int) $row['id'];
			if ( '' === (string) $row['previous_hash'] ) {
				if ( $seen_sealed ) {
					return [ 'status' => 'BROKEN', 'broken_id' => $id, 'error' => 'an unsealed row was inserted after the chain started' ] + $result;
				}
				++$result['unchained'];
				continue;
			}
			$seen_sealed = true;
			++$result['checked'];

			if ( ! hash_equals( $expected_prev, (string) $row['previous_hash'] ) ) {
				return [ 'status' => 'BROKEN', 'broken_id' => $id, 'error' => 'previous_hash does not match the preceding seal (row inserted, deleted or reordered)' ] + $result;
			}
			$expected = self::seal( (string) $row['previous_hash'], self::record_hash( (string) $row['session_id'], (string) $row['action'], (string) $row['entity_types_summary'], (string) $row['created_at'] ) );
			if ( ! hash_equals( $expected, (string) $row['current_hash'] ) ) {
				return [ 'status' => 'BROKEN', 'broken_id' => $id, 'error' => 'the seal does not match the row contents (a field was edited, or the salts changed)' ] + $result;
			}
			$expected_prev = (string) $row['current_hash'];
		}

		if ( $result['checked'] > 0 && '' === $stored_tip ) {
			return [ 'status' => 'BROKEN', 'error' => 'sealed rows exist, but the recorded chain tip is missing' ] + $result;
		}
		if ( '' !== $stored_tip && ! hash_equals( $stored_tip, $expected_prev ) ) {
			return [ 'status' => 'BROKEN', 'error' => 'the chain tip does not match the recorded tip (the newest rows were removed)' ] + $result;
		}
		if ( 0 === $result['checked'] ) {
			// Only rows from before the chain: nothing is sealed, so nothing can be verified. Not "INTACT".
			return [ 'status' => 'UNCHAINED_ONLY' ] + $result;
		}
		return $result;
	}
}
