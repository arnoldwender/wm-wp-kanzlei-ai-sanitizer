<?php
/**
 * WordPress 6.5+ Block Bindings (`wm-kanzlei/stats`) and GenerateBlocks 2.x Dynamic Tag (`{{wm_kanzlei_stat}}`).
 *
 * Exposes read-only aggregate operational counters from the sessions and audit tables without revealing prompts,
 * mappings or personal data.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\Kanzlei\Admin\AdminDashboard;
use WMCyber\Kanzlei\Audit\AuditChain;
use WMCyber\Kanzlei\Core\Settings;
use WMCyber\Kanzlei\Sanitizer\NerEngine;

final class EcosystemBridge {

	public const BLOCK_BINDING_SOURCE = 'wm-kanzlei/stats';

	public const GB_DYNAMIC_TAG = 'wm_kanzlei_stat';

	public function init(): void {
		add_action( 'init', [ $this, 'register_block_bindings' ] );
		add_action( 'init', [ $this, 'register_generateblocks_tag' ] );
		add_filter( 'generateblocks_dynamic_tag_replacement', [ $this, 'filter_generateblocks_replacement' ], 10, 2 );
	}

	public function register_block_bindings(): void {
		if ( ! function_exists( 'register_block_bindings_source' ) ) {
			return;
		}
		register_block_bindings_source(
			'wm-kanzlei/stats',
			[
				'label'              => __( 'WM Kanzlei Sanitizer Statistik', 'wm-kanzlei-ai-sanitizer' ),
				'get_value_callback' => [ $this, 'resolve_block_binding' ],
				'uses_context'       => [],
			]
		);
	}

	public function register_generateblocks_tag(): void {
		if ( ! class_exists( 'GenerateBlocks_Register_Dynamic_Tag' ) ) {
			return;
		}
		new \GenerateBlocks_Register_Dynamic_Tag(
			[
				'title'       => __( 'WM Kanzlei Sanitizer Kennzahl', 'wm-kanzlei-ai-sanitizer' ),
				'tag'         => self::GB_DYNAMIC_TAG,
				'type'        => 'site',
				'supports'    => [],
				'description' => __( 'Gibt aggregierte Zähler des KI-Sanitizers aus (sessions, replaced, audit_rows, active_types, chain_status).', 'wm-kanzlei-ai-sanitizer' ),
				'options'     => [
					'key' => [
						'type'    => 'select',
						'label'   => __( 'Kennzahl', 'wm-kanzlei-ai-sanitizer' ),
						'default' => 'replaced',
						'options' => [
							[
								'value' => 'replaced',
								'label' => __( 'Ersetzte Werte', 'wm-kanzlei-ai-sanitizer' ),
							],
							[
								'value' => 'sessions',
								'label' => __( 'Aufrufe', 'wm-kanzlei-ai-sanitizer' ),
							],
							[
								'value' => 'audit_rows',
								'label' => __( 'Protokollzeilen', 'wm-kanzlei-ai-sanitizer' ),
							],
							[
								'value' => 'active_types',
								'label' => __( 'Aktive Typen', 'wm-kanzlei-ai-sanitizer' ),
							],
							[
								'value' => 'chain_status',
								'label' => __( 'Kettenstatus', 'wm-kanzlei-ai-sanitizer' ),
							],
						],
					],
				],
				'return'      => [ $this, 'resolve_gb_dynamic_tag' ],
			]
		);
	}

	/**
	 * Resolve WP 6.5+ Block Bindings value (`wm-kanzlei/stats`).
	 *
	 * @param array<string, mixed> $source_args    Arguments passed to the binding (`key`).
	 * @param mixed                $block_instance Block instance (unused).
	 * @param string               $attribute_name Bound attribute name (unused).
	 */
	public function resolve_block_binding( array $source_args, $block_instance = null, string $attribute_name = '' ): ?string {
		$key = isset( $source_args['key'] ) && is_string( $source_args['key'] ) ? $source_args['key'] : 'replaced';
		return $this->stat_value( $key );
	}

	/**
	 * Resolve GenerateBlocks 2.x Dynamic Tag (`{{wm_kanzlei_stat key="replaced"}}`).
	 *
	 * @param array<string, mixed> $options  Tag options (`key`).
	 * @param array<string, mixed> $block    Block array (unused).
	 * @param mixed                $instance Block instance (unused).
	 */
	public function resolve_gb_dynamic_tag( array $options, array $block = [], $instance = null ): string {
		$key = isset( $options['key'] ) && is_string( $options['key'] ) ? $options['key'] : 'replaced';
		return $this->stat_value( $key ) ?? '';
	}

	/**
	 * Fallback replacement filter for GenerateBlocks dynamic tag evaluation.
	 *
	 * @param mixed $replacement Current replacement value.
	 * @param mixed $tag_details Parsed dynamic tag details.
	 */
	public function filter_generateblocks_replacement( mixed $replacement, mixed $tag_details = [] ): mixed {
		if ( ! is_array( $tag_details ) || ( $tag_details['tag'] ?? '' ) !== self::GB_DYNAMIC_TAG ) {
			return $replacement;
		}
		$options = isset( $tag_details['options'] ) && is_array( $tag_details['options'] ) ? $tag_details['options'] : [];
		$key     = isset( $options['key'] ) && is_string( $options['key'] ) ? $options['key'] : 'replaced';
		return $this->stat_value( $key ) ?? $replacement;
	}

	public function stat_value( string $key ): ?string {
		$counts = AdminDashboard::counts();
		$value  = match ( $key ) {
			'sessions'     => number_format_i18n( $counts['sessions'] ),
			'replaced'     => number_format_i18n( $counts['replaced'] ),
			'audit_rows'   => number_format_i18n( $counts['audit_rows'] ),
			'active_types' => count( Settings::enabled_types() ) . ' / ' . count( NerEngine::TYPES ),
			'chain_status' => AuditChain::verify()['status'],
			default        => null,
		};

		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filters a resolved operational counter exposed via Block Bindings or GenerateBlocks Dynamic Tags.
			 *
			 * @param string|null $value Resolved string value, or null for unknown keys.
			 * @param string      $key   Requested stat key.
			 */
			$filtered = apply_filters( 'wm_kanzlei_stat_value', $value, $key );
			$value    = is_string( $filtered ) || null === $filtered ? $filtered : $value;
		}

		return $value;
	}
}
