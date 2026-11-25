<?php
declare(strict_types=1);

namespace WMCyber\Kanzlei\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\Kanzlei\Sanitizer\NerEngine;
use WMCyber\Kanzlei\Sanitizer\TokenVault;

final class TokenVaultTest extends TestCase {
	private NerEngine $engine;
	private TokenVault $vault;

	protected function setUp(): void {
		parent::setUp();
		$this->engine = new NerEngine();
		$this->vault  = new TokenVault();
	}

	public function test_tokenize_and_rehydrate_cycle(): void {
		$original_prompt = 'Bitte erstellen Sie eine Zusammenfassung für Aktenzeichen 2 O 145/23 mit IBAN DE89370400440532013000.';
		$entities = $this->engine->detect_entities( $original_prompt );

		$tokenized = $this->vault->tokenize( $original_prompt, $entities, 'test-salt-123' );

		$this->assertStringNotContainsString( '2 O 145/23', $tokenized['sanitized_text'] );
		$this->assertStringNotContainsString( 'DE89370400440532013000', $tokenized['sanitized_text'] );
		$this->assertStringContainsString( '{{AKTENZEICHEN_', $tokenized['sanitized_text'] );
		$this->assertStringContainsString( '{{IBAN_', $tokenized['sanitized_text'] );

		// Simulate LLM returning response with placeholders preserved
		$simulated_llm_response = 'Gutachten für Fall ' . array_key_first( $tokenized['mapping'] ) . ' fertiggestellt.';
		$rehydrated = $this->vault->rehydrate( $simulated_llm_response, $tokenized['mapping'] );

		$this->assertStringContainsString( $tokenized['mapping'][ array_key_first( $tokenized['mapping'] ) ], $rehydrated );
	}
}
