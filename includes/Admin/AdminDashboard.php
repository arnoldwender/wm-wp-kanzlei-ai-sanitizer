<?php
/**
 * Admin screen, dashboard widget and settings.
 *
 * Rewritten on 2026-09-15 from a Spanish screen that said "100% RGPD COMPLIANT", "CUSTODIA ACTIVA" and "Anonimización
 * en memoria", counted at most 50 audit rows as "Peticiones protegidas", promised encryption before every AI call,
 * offered an AI provider and a retention time nothing used, showed a simulator with unsalted md5 placeholders, and
 * let any user with edit_posts write four made-up rows (one with a client name) into the audit log. The screen now
 * shows what the database holds and what the code does, in German; the log and the settings need manage_options.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WMCyber\Kanzlei\Audit\AuditChain;
use WMCyber\Kanzlei\Core\Settings;
use WMCyber\Kanzlei\Sanitizer\NerEngine;
use WMCyber\Kanzlei\Sanitizer\TokenVault;

final class AdminDashboard {

	public const PAGE = 'wm-kanzlei-sanitizer';

	/** Simulator sample: every detected type and the leaks the docs list. */
	public const SAMPLE_TEXT = "Sehr geehrte Frau Richterin,\nin Sachen Müller ./. Schneider GmbH, Az. 4 O 311/24, vertreten wir Herrn Jonas Müller, Lindenweg 7, 39576 Stendal, geb. 14.02.1979. Er ist unter 0391 1234567 und j.mueller@example.org erreichbar. Die Klageforderung von 23.400,00 € ist auf DE89 3704 0044 0532 0130 00 zu zahlen. Müller benennt Frau Dr. Anna Weiß als Zeugin.";

	public function __construct(
		private readonly NerEngine $ner_engine,
		private readonly TokenVault $token_vault
	) {}

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'register_admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_init', [ $this, 'handle_form_actions' ] );
		add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
	}

	public function register_settings(): void {
		if ( function_exists( 'register_setting' ) ) {
			register_setting(
				'wm_kanzlei_settings_group',
				Settings::DELETE_DATA_OPTION,
				[
					'type'              => 'boolean',
					'sanitize_callback' => static fn( $value ): string => ! empty( $value ) ? '1' : '0',
					'default'           => '0',
				]
			);
		}
	}

	/** Type => German label. */
	public static function type_labels(): array {
		return [
			'AKTENZEICHEN' => __( 'Aktenzeichen', 'wm-kanzlei-ai-sanitizer' ),
			'IBAN'         => __( 'IBAN', 'wm-kanzlei-ai-sanitizer' ),
			'EMAIL'        => __( 'E-Mail-Adressen', 'wm-kanzlei-ai-sanitizer' ),
			'STEUER_ID'    => __( 'Steuer-ID (11 Ziffern)', 'wm-kanzlei-ai-sanitizer' ),
			'PHONE'        => __( 'Telefonnummern', 'wm-kanzlei-ai-sanitizer' ),
			'PERSON_NAME'  => __( 'Namen nach Anrede oder Rolle', 'wm-kanzlei-ai-sanitizer' ),
			'GELDBETRAG'   => __( 'Geldbeträge', 'wm-kanzlei-ai-sanitizer' ),
		];
	}

	/** What the patterns do not find, as measured on 2026-09-15. */
	public static function not_detected(): string {
		return __( 'Nicht erkannt werden: Namen ohne Anrede oder Rolle („Max Mustermann“), Firmennamen, Adressen, Geburtsdaten, Steuernummern, USt-IdNr., Sozialversicherungs-, Krankenversicherungs- und Ausweisnummern, Registernummern, Kennzeichen, Gesundheitsangaben und interne Aktenzeichen wie „2024/0815-MK“. Den ersetzten Text vor dem Versand selbst prüfen.', 'wm-kanzlei-ai-sanitizer' );
	}

	public function register_dashboard_widget(): void {
		if ( ! current_user_can( 'edit_posts' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'wm_kanzlei_ai_widget',
			__( 'WM Kanzlei AI Sanitizer', 'wm-kanzlei-ai-sanitizer' ),
			[ $this, 'render_dashboard_widget' ]
		);
	}

	/** @return array{sessions: int, replaced: int, audit_rows: int} Counts from the tables, 0 when a table is missing. */
	public static function counts(): array {
		global $wpdb;
		$sessions = $wpdb->prefix . 'wm_kanzlei_sessions';
		$out      = [ 'sessions' => 0, 'replaced' => 0, 'audit_rows' => 0 ];
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $sessions ) ) ) === $sessions ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$out['sessions'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $sessions ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$out['replaced'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(SUM(entities_redacted), 0) FROM %i', $sessions ) );
		}
		if ( AuditChain::table_present() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$out['audit_rows'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', AuditChain::table() ) );
		}
		return $out;
	}

	public function render_dashboard_widget(): void {
		$counts = self::counts();
		?>
		<div class="wm-dash-widget-box" data-wm-theme="<?php echo esc_attr( function_exists( 'wm_get_suite_theme' ) ? wm_get_suite_theme() : 'cyber-events' ); ?>">
			<div class="wm-dash-banner">
				<span class="wm-dash-banner-icon dashicons dashicons-shield" aria-hidden="true"></span>
				<div>
					<div class="wm-dash-banner-title"><?php esc_html_e( 'Platzhalter statt erkannter Werte', 'wm-kanzlei-ai-sanitizer' ); ?></div>
					<div class="wm-dash-banner-sub"><?php esc_html_e( 'Ersetzt Aktenzeichen, IBAN, E-Mail, Steuer-ID, Telefonnummern, Namen nach einer Anrede und Geldbeträge. Sendet nichts an KI-Anbieter.', 'wm-kanzlei-ai-sanitizer' ); ?></div>
				</div>
			</div>
			<div class="wm-dash-kpi-grid">
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( number_format_i18n( $counts['sessions'] ) ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Aufrufe', 'wm-kanzlei-ai-sanitizer' ); ?></div>
				</div>
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( number_format_i18n( $counts['replaced'] ) ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Ersetzte Werte', 'wm-kanzlei-ai-sanitizer' ); ?></div>
				</div>
				<div class="wm-dash-kpi-card">
					<div class="wm-dash-kpi-val"><?php echo esc_html( (string) count( Settings::enabled_types() ) ); ?> / <?php echo esc_html( (string) count( NerEngine::TYPES ) ); ?></div>
					<div class="wm-dash-kpi-lbl"><?php esc_html_e( 'Aktive Typen', 'wm-kanzlei-ai-sanitizer' ); ?></div>
				</div>
			</div>
			<div class="wm-dash-actions">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::PAGE . '&tab=simulator' ) ); ?>" class="wm-dash-btn">
					<span><?php esc_html_e( 'Simulator öffnen', 'wm-kanzlei-ai-sanitizer' ); ?></span> <span aria-hidden="true">&rarr;</span>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Family menu icon: a monochrome hub-and-spoke mark, filled shapes only so the WordPress
	 * svg-painter can recolour it with the admin colour scheme. Placeholder until the family
	 * icon is decided (hackaton plan D12).
	 */
	public static function family_menu_icon(): string {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><circle cx="10" cy="10" r="2.6" fill="black"/><circle cx="10" cy="3" r="1.8" fill="black"/><circle cx="16.1" cy="13.5" r="1.8" fill="black"/><circle cx="3.9" cy="13.5" r="1.8" fill="black"/><rect x="9.3" y="4.5" width="1.4" height="3.4" fill="black"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(-60 10 10)"/><rect x="9.3" y="12.1" width="1.4" height="3.4" fill="black" transform="rotate(60 10 10)"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}

	public function register_admin_menu(): void {
		add_menu_page(
			__( 'Kanzlei AI Sanitizer', 'wm-kanzlei-ai-sanitizer' ),
			__( 'KI-Sanitizer', 'wm-kanzlei-ai-sanitizer' ),
			'edit_posts',
			self::PAGE,
			[ $this, 'render_dashboard_page' ],
			self::family_menu_icon(),
			32
		);
	}

	/**
	 * Family sheets on the plugin's page and on the WordPress dashboard, where the widget renders. Until 2026-09-15
	 * only the plugin page loaded them, so the widget's classes were unstyled on the dashboard.
	 */
	public function enqueue_admin_assets( string $hook ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		$page = sanitize_key( wp_unslash( $_GET['page'] ?? '' ) );
		if ( 'index.php' !== $hook && ! str_contains( $hook, 'wm-kanzlei' ) && ! str_contains( $page, 'wm-kanzlei' ) ) {
			return;
		}

		$root    = dirname( __DIR__, 2 ) . '/assets/css/';
		$version = static fn( string $file ): string => is_file( $root . $file ) ? (string) filemtime( $root . $file ) : WM_KANZLEI_VERSION;
		wp_enqueue_style( 'wm-admin-tokens', WM_KANZLEI_URL . 'assets/css/wm-admin-tokens.css', [], $version( 'wm-admin-tokens.css' ) );
		wp_enqueue_style( 'wm-admin-ui', WM_KANZLEI_URL . 'assets/css/wm-admin-ui.css', [ 'wm-admin-tokens' ], $version( 'wm-admin-ui.css' ) );
	}

	/**
	 * Settings and the "all types on" preset: manage_options and a nonce per form. The demo seeder that wrote four
	 * made-up rows into the audit log for any edit_posts user with a shared nonce was removed on 2026-09-15.
	 */
	public function handle_form_actions(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the nonce is checked per action below.
		$action = isset( $_POST['wm_kanzlei_action'] ) ? sanitize_key( wp_unslash( $_POST['wm_kanzlei_action'] ) ) : '';
		if ( '' === $action ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Keine Berechtigung.', 'wm-kanzlei-ai-sanitizer' ), 403 );
		}

		if ( 'save_settings' === $action ) {
			check_admin_referer( 'wm_kanzlei_save_settings', 'wm_kanzlei_nonce' );
			$posted = [];
			foreach ( array_keys( Settings::SWITCHES ) as $key ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked above.
				$posted[ $key ] = isset( $_POST[ $key ] ) ? '1' : '';
			}
			Settings::save_switches( $posted );
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked above.
			Settings::save_delete_data_on_uninstall( ! empty( $_POST[ Settings::DELETE_DATA_OPTION ] ) );
			wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE . '&tab=settings&saved=1' ) );
			exit;
		}

		if ( 'enable_all' === $action ) {
			check_admin_referer( 'wm_kanzlei_enable_all', 'wm_kanzlei_nonce' );
			Settings::enable_all();
			wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE . '&tab=settings&saved=1' ) );
			exit;
		}
	}

	/** Tab slug => label, capability and dashicon. */
	private function tabs(): array {
		return [
			'overview'  => [ 'label' => __( 'Übersicht', 'wm-kanzlei-ai-sanitizer' ), 'cap' => 'edit_posts', 'icon' => 'dashicons-info-outline' ],
			'simulator' => [ 'label' => __( 'Simulator', 'wm-kanzlei-ai-sanitizer' ), 'cap' => 'edit_posts', 'icon' => 'dashicons-editor-code' ],
			'settings'  => [ 'label' => __( 'Einstellungen', 'wm-kanzlei-ai-sanitizer' ), 'cap' => 'manage_options', 'icon' => 'dashicons-admin-settings' ],
			'log'       => [ 'label' => __( 'Protokoll', 'wm-kanzlei-ai-sanitizer' ), 'cap' => 'manage_options', 'icon' => 'dashicons-list-view' ],
			'help'      => [ 'label' => __( 'Begriffe', 'wm-kanzlei-ai-sanitizer' ), 'cap' => 'edit_posts', 'icon' => 'dashicons-book' ],
		];
	}

	/**
	 * Run the simulator on the posted text.
	 *
	 * @return array{text: string, result: ?array, error: ?string}
	 */
	public function simulate(): array {
		$state = [ 'text' => '', 'result' => null, 'error' => null ];
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified before the text is used.
		if ( ! isset( $_POST['wm_kanzlei_sim_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wm_kanzlei_sim_nonce'] ) ), 'wm_kanzlei_sim' ) ) {
			return $state;
		}
		if ( isset( $_POST['wm_sim_load_sample'] ) ) {
			$state['text'] = self::SAMPLE_TEXT;
			return $state;
		}
		// Raw on purpose: the simulator shows what the engine does with the text as typed; output is escaped.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$state['text'] = isset( $_POST['wm_sim_prompt'] ) && is_string( $_POST['wm_sim_prompt'] ) ? wp_unslash( $_POST['wm_sim_prompt'] ) : '';
		if ( '' === $state['text'] ) {
			return $state;
		}
		try {
			$entities = $this->ner_engine->detect_entities( $state['text'], Settings::enabled_types() );
		} catch ( \Throwable $e ) {
			$state['error'] = $e->getMessage();
			return $state;
		}
		// Same vault and a random salt, as on the REST route. Until 2026-09-15 the simulator used unsalted md5
		// prefixes, from which "14.500 EUR" could be recovered by trying amounts.
		$state['result'] = [
			'entities'  => $entities,
			'tokenized' => $this->token_vault->tokenize( $state['text'], $entities, bin2hex( random_bytes( 16 ) ) ),
			'warnings'  => $this->ner_engine->collect_review_warnings( $state['text'], $entities ),
		];
		return $state;
	}

	public function render_dashboard_page(): void {
		$tabs = $this->tabs();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab routing.
		$current = sanitize_key( wp_unslash( $_GET['tab'] ?? 'overview' ) );
		if ( ! isset( $tabs[ $current ] ) || ! current_user_can( $tabs[ $current ]['cap'] ) ) {
			$current = 'overview';
		}
		?>
		<div class="wrap wm-admin wm-kanzlei-admin-wrap">
			<header class="wm-admin-header">
				<div class="wm-header-brand">
					<div class="wm-header-icon">
						<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" focusable="false"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					</div>
					<div>
						<h1><?php esc_html_e( 'Kanzlei AI Sanitizer', 'wm-kanzlei-ai-sanitizer' ); ?></h1>
						<p class="wm-subtitle"><?php esc_html_e( 'Ersetzt erkannte Werte in einem Text durch Platzhalter und setzt sie in der Antwort wieder ein. Das Plugin sendet nichts an KI-Anbieter.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
					</div>
				</div>
				<div class="wm-header-badges">
					<span class="wm-badge-family" title="<?php esc_attr_e( 'Teil der WM-Suite-Pluginfamilie', 'wm-kanzlei-ai-sanitizer' ); ?>">
						<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="4" r="2"/><circle cx="19" cy="16" r="2"/><circle cx="5" cy="16" r="2"/><path d="M12 7v2M13.9 13.2l3.4 2M10.1 13.2l-3.4 2"/></svg>
						<?php esc_html_e( 'WM Suite', 'wm-kanzlei-ai-sanitizer' ); ?>
						<span class="wm-badge-family-state"><?php echo defined( 'WM_SUITE_HUB_VERSION' ) ? esc_html__( 'Hub', 'wm-kanzlei-ai-sanitizer' ) : esc_html__( 'Standalone', 'wm-kanzlei-ai-sanitizer' ); ?></span>
					</span>
					<span class="wm-badge wm-badge-ghost"><?php esc_html_e( 'KEINE EXTERNEN ANFRAGEN', 'wm-kanzlei-ai-sanitizer' ); ?></span>
				</div>
			</header>

			<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display flag after a redirect. ?>
			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Einstellungen gespeichert.', 'wm-kanzlei-ai-sanitizer' ); ?></p></div>
			<?php endif; ?>

			<nav class="wm-nav-tabs" aria-label="<?php esc_attr_e( 'Bereiche', 'wm-kanzlei-ai-sanitizer' ); ?>">
				<?php foreach ( $tabs as $slug => $tab ) : ?>
					<?php if ( current_user_can( $tab['cap'] ) ) : ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::PAGE . '&tab=' . $slug ) ); ?>" class="wm-tab-link <?php echo $current === $slug ? 'active' : ''; ?>"<?php echo $current === $slug ? ' aria-current="page"' : ''; ?>>
							<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>" aria-hidden="true"></span> <?php echo esc_html( $tab['label'] ); ?>
						</a>
					<?php endif; ?>
				<?php endforeach; ?>
			</nav>

			<?php
			switch ( $current ) {
				case 'simulator':
					$this->render_simulator();
					break;
				case 'settings':
					$this->render_settings();
					break;
				case 'log':
					$this->render_log();
					break;
				case 'help':
					$this->render_help();
					break;
				default:
					$this->render_overview();
			}
			?>
		</div>
		<?php
	}

	private function render_overview(): void {
		$counts = self::counts();
		$labels = self::type_labels();
		$active = array_map( static fn( string $t ): string => $labels[ $t ] ?? $t, Settings::enabled_types() );
		?>
		<div class="wm-tab-content">
			<div class="wm-grid-3">
				<div class="wm-stat-card">
					<span class="wm-stat-label"><?php esc_html_e( 'Aufrufe von /sanitize', 'wm-kanzlei-ai-sanitizer' ); ?></span>
					<span class="wm-stat-value"><?php echo esc_html( number_format_i18n( $counts['sessions'] ) ); ?></span>
					<span class="wm-stat-delta"><?php esc_html_e( 'Zeilen in der Sitzungstabelle', 'wm-kanzlei-ai-sanitizer' ); ?></span>
				</div>
				<div class="wm-stat-card">
					<span class="wm-stat-label"><?php esc_html_e( 'Ersetzte Werte', 'wm-kanzlei-ai-sanitizer' ); ?></span>
					<span class="wm-stat-value"><?php echo esc_html( number_format_i18n( $counts['replaced'] ) ); ?></span>
					<span class="wm-stat-delta"><?php esc_html_e( 'Summe über alle Aufrufe', 'wm-kanzlei-ai-sanitizer' ); ?></span>
				</div>
				<div class="wm-stat-card">
					<span class="wm-stat-label"><?php esc_html_e( 'Protokollzeilen', 'wm-kanzlei-ai-sanitizer' ); ?></span>
					<span class="wm-stat-value"><?php echo esc_html( number_format_i18n( $counts['audit_rows'] ) ); ?></span>
					<span class="wm-stat-delta"><?php esc_html_e( 'alle Zeilen, auch aus früheren Versionen', 'wm-kanzlei-ai-sanitizer' ); ?></span>
				</div>
			</div>

			<div class="wm-card">
				<h2><?php esc_html_e( 'Was das Plugin tut', 'wm-kanzlei-ai-sanitizer' ); ?></h2>
				<ol>
					<li><?php esc_html_e( 'POST /wp-json/wm-kanzlei/v1/sanitize (Rolle mit edit_posts) sucht im Text nach den aktiven Typen, ersetzt jeden Wert durch einen Platzhalter wie {{IBAN_…}} und gibt den Text, die Zuordnung Platzhalter → Wert und die Sitzungskennung zurück. Die Zuordnung wird nicht gespeichert.', 'wm-kanzlei-ai-sanitizer' ); ?></li>
					<li><?php esc_html_e( 'Den ersetzten Text sendet die Anwendung, die das Plugin aufruft, selbst an einen KI-Dienst. POST /proxy antwortet mit 501: Das Plugin ist mit keinem Anbieter verbunden.', 'wm-kanzlei-ai-sanitizer' ); ?></li>
					<li><?php esc_html_e( 'POST /rehydrate setzt die Werte mit der zurückgesandten Zuordnung wieder in die Antwort ein.', 'wm-kanzlei-ai-sanitizer' ); ?></li>
					<li><?php esc_html_e( 'Jeder Aufruf von /sanitize schreibt eine Sitzungszeile (Nutzer, Anzahl, Zeit) und eine Protokollzeile (gefundene Typen) mit HMAC-Siegel, das an die vorige Zeile gekettet ist. Der Text selbst wird nicht gespeichert.', 'wm-kanzlei-ai-sanitizer' ); ?></li>
				</ol>
				<p><strong><?php esc_html_e( 'Aktive Typen:', 'wm-kanzlei-ai-sanitizer' ); ?></strong> <?php echo esc_html( $active ? implode( ', ', $active ) : __( 'keine', 'wm-kanzlei-ai-sanitizer' ) ); ?></p>
				<div class="wm-inline-notice"><?php echo esc_html( self::not_detected() ); ?></div>
			</div>
		</div>
		<?php
	}

	private function render_simulator(): void {
		$sim    = $this->simulate();
		$labels = self::type_labels();
		?>
		<div class="wm-tab-content">
			<div class="wm-card">
				<h2><?php esc_html_e( 'Simulator', 'wm-kanzlei-ai-sanitizer' ); ?></h2>
				<p class="wm-card-caption"><?php esc_html_e( 'Zeigt, was /sanitize mit einem Text macht, mit den aktiven Typen. Hier wird nichts gespeichert und nichts protokolliert.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				<form method="post" action="">
					<?php wp_nonce_field( 'wm_kanzlei_sim', 'wm_kanzlei_sim_nonce' ); ?>
					<label class="wm-label" for="wm-sim-textarea"><?php esc_html_e( 'Text', 'wm-kanzlei-ai-sanitizer' ); ?></label>
					<textarea id="wm-sim-textarea" name="wm_sim_prompt" rows="7" class="wm-textarea"><?php echo esc_textarea( $sim['text'] ); ?></textarea>
					<p>
						<button type="submit" class="button button-primary"><?php esc_html_e( 'Werte ersetzen', 'wm-kanzlei-ai-sanitizer' ); ?></button>
						<button type="submit" name="wm_sim_load_sample" value="1" class="button"><?php esc_html_e( 'Beispieltext laden', 'wm-kanzlei-ai-sanitizer' ); ?></button>
					</p>
				</form>

				<?php if ( null !== $sim['error'] ) : ?>
					<div class="notice notice-error inline"><p><?php echo esc_html( $sim['error'] ); ?></p></div>
				<?php elseif ( null !== $sim['result'] ) : ?>
					<?php if ( ! empty( $sim['result']['warnings'] ) ) : ?>
						<div class="notice notice-warning inline">
							<p><strong><?php esc_html_e( 'Prüfhinweise', 'wm-kanzlei-ai-sanitizer' ); ?></strong></p>
							<ul>
								<?php foreach ( $sim['result']['warnings'] as $warning ) : ?>
									<li>
										<code><?php echo esc_html( (string) ( $warning['span'] ?? '' ) ); ?></code>
										(<?php echo esc_html( (string) ( $warning['code'] ?? '' ) ); ?>):
										<?php echo esc_html( (string) ( $warning['message'] ?? '' ) ); ?>
									</li>
								<?php endforeach; ?>
							</ul>
						</div>
					<?php endif; ?>
					<h3><?php esc_html_e( 'Ersetzter Text', 'wm-kanzlei-ai-sanitizer' ); ?></h3>
					<pre class="wm-code-block"><?php echo esc_html( $sim['result']['tokenized']['sanitized_text'] ); ?></pre>
					<h3>
						<?php
						/* translators: %d: number of values replaced */
						echo esc_html( sprintf( _n( '%d Wert ersetzt', '%d Werte ersetzt', count( $sim['result']['entities'] ), 'wm-kanzlei-ai-sanitizer' ), count( $sim['result']['entities'] ) ) );
						?>
					</h3>
					<?php if ( $sim['result']['entities'] ) : ?>
						<table class="wm-table widefat striped">
							<thead><tr><th><?php esc_html_e( 'Typ', 'wm-kanzlei-ai-sanitizer' ); ?></th><th><?php esc_html_e( 'Wert', 'wm-kanzlei-ai-sanitizer' ); ?></th></tr></thead>
							<tbody>
								<?php foreach ( $sim['result']['entities'] as $entity ) : ?>
									<tr><td><?php echo esc_html( $labels[ $entity['type'] ] ?? $entity['type'] ); ?></td><td><code><?php echo esc_html( $entity['value'] ); ?></code></td></tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
					<div class="wm-inline-notice"><?php echo esc_html( self::not_detected() ); ?></div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	private function render_settings(): void {
		$switches = Settings::switches();
		$labels   = self::type_labels();
		?>
		<div class="wm-tab-content">
			<div class="wm-card">
				<h2><?php esc_html_e( 'Welche Typen ersetzt werden', 'wm-kanzlei-ai-sanitizer' ); ?></h2>
				<p class="wm-card-caption"><?php esc_html_e( 'Gilt für /sanitize, WP-CLI und den Simulator. Ein abgeschalteter Typ bleibt im Text stehen.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				<form method="post" action="">
					<?php wp_nonce_field( 'wm_kanzlei_save_settings', 'wm_kanzlei_nonce' ); ?>
					<input type="hidden" name="wm_kanzlei_action" value="save_settings" />
					<fieldset>
						<legend class="screen-reader-text"><?php esc_html_e( 'Typen', 'wm-kanzlei-ai-sanitizer' ); ?></legend>
						<?php foreach ( Settings::SWITCHES as $key => $type ) : ?>
							<p>
								<label class="wm-toggle-label">
									<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" value="1" <?php checked( $switches[ $key ] ); ?> />
									<?php echo esc_html( $labels[ $type ] ?? $type ); ?>
								</label>
							</p>
						<?php endforeach; ?>
					</fieldset>
					<fieldset>
						<legend class="screen-reader-text"><?php esc_html_e( 'Deinstallation', 'wm-kanzlei-ai-sanitizer' ); ?></legend>
						<h3><?php esc_html_e( 'Deinstallation', 'wm-kanzlei-ai-sanitizer' ); ?></h3>
						<p>
							<label class="wm-toggle-label">
								<input type="checkbox" name="<?php echo esc_attr( Settings::DELETE_DATA_OPTION ); ?>" value="1" <?php checked( Settings::delete_data_on_uninstall() ); ?> />
								<?php esc_html_e( 'Beim Löschen des Plugins alle Optionen sowie die Sitzungs- und Protokolltabellen entfernen (Standard: aus, Protokoll bleibt erhalten)', 'wm-kanzlei-ai-sanitizer' ); ?>
							</label>
						</p>
					</fieldset>
					<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Speichern', 'wm-kanzlei-ai-sanitizer' ); ?></button></p>
				</form>
				<form method="post" action="">
					<?php wp_nonce_field( 'wm_kanzlei_enable_all', 'wm_kanzlei_nonce' ); ?>
					<input type="hidden" name="wm_kanzlei_action" value="enable_all" />
					<p><button type="submit" class="button"><?php esc_html_e( 'Alle Typen einschalten', 'wm-kanzlei-ai-sanitizer' ); ?></button></p>
				</form>
				<div class="wm-inline-notice"><?php esc_html_e( 'Es gibt keine Einstellung für einen KI-Anbieter oder eine Aufbewahrungszeit: Das Plugin ist mit keinem Anbieter verbunden und speichert die Zuordnung nicht. Sitzungs- und Protokollzeilen bleiben beim Löschen des Plugins erhalten, sofern die Option zur Deinstallation oben nicht eingeschaltet ist.', 'wm-kanzlei-ai-sanitizer' ); ?></div>
			</div>
		</div>
		<?php
	}

	private function render_log(): void {
		global $wpdb;
		$rows  = [];
		$chain = AuditChain::verify();
		if ( AuditChain::table_present() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, session_id, action, entity_types_summary, previous_hash, created_at FROM %i ORDER BY id DESC LIMIT 50', AuditChain::table() ), ARRAY_A );
		}
		$status_text = [
			'INTACT'         => __( 'Kette geprüft: jede versiegelte Zeile passt zu ihrem Siegel und zur vorigen Zeile.', 'wm-kanzlei-ai-sanitizer' ),
			'EMPTY_CHAIN'    => __( 'Noch keine Protokollzeilen.', 'wm-kanzlei-ai-sanitizer' ),
			'UNCHAINED_ONLY' => __( 'Nur Zeilen aus der Zeit vor der Kette: nichts ist versiegelt, nichts lässt sich prüfen.', 'wm-kanzlei-ai-sanitizer' ),
			'BROKEN'         => __( 'Kette gebrochen.', 'wm-kanzlei-ai-sanitizer' ),
		];
		?>
		<div class="wm-tab-content">
			<div class="wm-card">
				<h2><?php esc_html_e( 'Protokoll', 'wm-kanzlei-ai-sanitizer' ); ?></h2>
				<div class="<?php echo esc_attr( 'BROKEN' === $chain['status'] ? 'notice notice-error inline' : 'wm-inline-notice' ); ?>">
					<p>
						<strong><?php echo esc_html( $chain['status'] ); ?></strong> ·
						<?php echo esc_html( $status_text[ $chain['status'] ] ?? '' ); ?>
						<?php if ( null !== $chain['error'] ) : ?>
							<?php echo esc_html( $chain['error'] . ( null !== $chain['broken_id'] ? ' (#' . $chain['broken_id'] . ')' : '' ) ); ?>
						<?php endif; ?>
						<?php
						/* translators: 1: sealed rows, 2: rows written before the chain */
						echo esc_html( sprintf( __( '%1$d versiegelt, %2$d vor der Kette.', 'wm-kanzlei-ai-sanitizer' ), $chain['checked'], $chain['unchained'] ) );
						?>
					</p>
				</div>
				<p class="wm-card-caption"><?php esc_html_e( 'Eine Zeile hält fest, dass /sanitize aufgerufen wurde und welche Typen gefunden wurden, nicht den Text und nicht, ob oder wohin er gesendet wurde. Zeilen vor der Kette stammen aus früheren Versionen, darunter Beispielzeilen des entfernten Demo-Knopfs. Wer die Datenbank und wp-config.php schreiben kann, kann die Kette neu versiegeln.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				<?php if ( $rows ) : ?>
					<table class="wm-table widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Nr.', 'wm-kanzlei-ai-sanitizer' ); ?></th>
								<th><?php esc_html_e( 'Sitzung', 'wm-kanzlei-ai-sanitizer' ); ?></th>
								<th><?php esc_html_e( 'Aktion', 'wm-kanzlei-ai-sanitizer' ); ?></th>
								<th><?php esc_html_e( 'Gefundene Typen', 'wm-kanzlei-ai-sanitizer' ); ?></th>
								<th><?php esc_html_e( 'Kette', 'wm-kanzlei-ai-sanitizer' ); ?></th>
								<th><?php esc_html_e( 'Zeit (UTC)', 'wm-kanzlei-ai-sanitizer' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $row['id'] ); ?></td>
									<td><code><?php echo esc_html( substr( (string) $row['session_id'], 0, 12 ) ); ?></code></td>
									<td><?php echo esc_html( (string) $row['action'] ); ?></td>
									<td><?php echo esc_html( (string) $row['entity_types_summary'] ); ?></td>
									<td><?php echo '' === (string) $row['previous_hash'] ? esc_html__( 'vor der Kette', 'wm-kanzlei-ai-sanitizer' ) : esc_html__( 'versiegelt', 'wm-kanzlei-ai-sanitizer' ); ?></td>
									<td><?php echo esc_html( (string) $row['created_at'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php else : ?>
					<p><?php esc_html_e( 'Keine Zeilen.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	private function render_help(): void {
		?>
		<div class="wm-tab-content">
			<div class="wm-glossary-grid">
				<div class="wm-glossary-card">
					<div class="wm-glossary-term"><?php esc_html_e( 'Platzhalter', 'wm-kanzlei-ai-sanitizer' ); ?></div>
					<p class="wm-glossary-def"><?php esc_html_e( 'Ein Wert wird durch {{TYP_…}} ersetzt. Der Teil nach dem Typ ist ein HMAC des Werts mit einem Zufallsschlüssel je Aufruf; ohne die Zuordnung lässt er sich nicht zurückrechnen.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				</div>
				<div class="wm-glossary-card">
					<div class="wm-glossary-term"><?php esc_html_e( 'Pseudonymisierung, nicht Anonymisierung', 'wm-kanzlei-ai-sanitizer' ); ?></div>
					<p class="wm-glossary-def"><?php esc_html_e( 'Wer die Zuordnung hat, stellt die Werte wieder her. Solche Daten nennt die DSGVO pseudonymisiert (Art. 4 Nr. 5); nach Erwägungsgrund 26 bleiben sie Informationen über eine identifizierbare Person. Werte, die das Plugin nicht erkennt, bleiben ohnehin im Klartext.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				</div>
				<div class="wm-glossary-card">
					<div class="wm-glossary-term"><?php esc_html_e( 'Wiedereinsetzen', 'wm-kanzlei-ai-sanitizer' ); ?></div>
					<p class="wm-glossary-def"><?php esc_html_e( '/rehydrate ersetzt die Platzhalter in einer Antwort auf dem WordPress-Server durch die Werte aus der mitgesandten Zuordnung.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				</div>
				<div class="wm-glossary-card">
					<div class="wm-glossary-term"><?php esc_html_e( 'Was das Plugin nicht entscheidet', 'wm-kanzlei-ai-sanitizer' ); ?></div>
					<p class="wm-glossary-def"><?php esc_html_e( 'Ob ein Text an einen Dienstleister gehen darf und unter welchen Bedingungen (§ 203 StGB, § 43e BRAO, DSGVO), entscheidet das Plugin nicht, und es stellt keine Bescheinigung darüber aus.', 'wm-kanzlei-ai-sanitizer' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}
}
