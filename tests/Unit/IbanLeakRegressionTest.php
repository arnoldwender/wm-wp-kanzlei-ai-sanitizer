<?php
/**
 * Regression: an IBAN must never reach the model in readable fragments.
 *
 * The IBAN pattern demanded groups of exactly four digits. A German IBAN is DE + 2 check digits
 * + 18 BBAN digits, and 18 is not a multiple of four, so the pattern matched nothing at all.
 * Every IBAN then fell through to the phone pattern, which claimed a slice of it — the vault
 * tokenised that slice and passed the rest of the account number through untouched.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WMCyber\Kanzlei\Sanitizer\NerEngine;

final class IbanLeakRegressionTest extends TestCase {

	private NerEngine $engine;

	protected function setUp(): void {
		parent::setUp();
		$this->engine = new NerEngine();
	}

	/**
	 * IBANs from several countries, with and without spacing, must all be detected whole.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function iban_provider(): array {
		return array(
			'DE unspaced' => array( 'DE89370400440532013000' ),
			'DE spaced'   => array( 'DE89 3704 0044 0532 0130 00' ),
			'AT'          => array( 'AT611904300234573201' ),
			'FR alnum'    => array( 'FR1420041010050500013M02606' ),
			'GB alnum'    => array( 'GB29NWBK60161331926819' ),
			// Added 2026-09-15: the phone pattern cut these into readable fragments.
			'DE lowercase spaced' => array( 'de89 3704 0044 0532 0130 00' ),
			'DE hyphenated'       => array( 'DE89-3704-0044-0532-0130-00' ),
		);
	}

	/**
	 * Letters are valid IBAN characters, so capitalised words after an IBAN were captured with it. The mod-97 check
	 * cuts the match back to the account number (2026-09-15).
	 */
	public function test_following_capitalised_words_are_not_part_of_the_iban(): void {
		$entities = $this->engine->detect_entities( 'IBAN DE89370400440532013000 BITTE BIS MONTAG' );
		$ibans    = array_values( array_filter( $entities, static fn( $e ) => 'IBAN' === $e['type'] ) );

		$this->assertCount( 1, $ibans );
		$this->assertSame( 'DE89370400440532013000', $ibans[0]['value'] );
	}

	/**
	 * @param string $iban IBAN under test.
	 */
	#[DataProvider( 'iban_provider' )]
	public function test_iban_is_detected_as_a_single_whole_entity( string $iban ): void {
		$text     = "Bitte überweisen Sie das Honorar an {$iban} bis Monatsende.";
		$entities = $this->engine->detect_entities( $text );

		$ibans = array_values( array_filter( $entities, static fn( $e ) => 'IBAN' === $e['type'] ) );

		$this->assertCount( 1, $ibans, "Expected exactly one IBAN entity for {$iban}" );
		$this->assertSame( $iban, $ibans[0]['value'], 'The whole IBAN must be captured, not a fragment' );
	}

	/**
	 * @param string $iban IBAN under test.
	 */
	#[DataProvider( 'iban_provider' )]
	public function test_no_other_pattern_claims_part_of_an_iban( string $iban ): void {
		$text     = "Bitte überweisen Sie das Honorar an {$iban} bis Monatsende.";
		$entities = $this->engine->detect_entities( $text );

		$iban_start = strpos( $text, $iban );
		$iban_end   = $iban_start + strlen( $iban );

		// Assert unconditionally: without this the test passes vacuously when detection returns
		// nothing at all, which is exactly the state the bug produced.
		$this->assertNotEmpty(
			array_filter( $entities, static fn( $e ) => 'IBAN' === $e['type'] ),
			'Detection returned no IBAN — the overlap check below would pass on an empty set.'
		);

		foreach ( $entities as $entity ) {
			if ( 'IBAN' === $entity['type'] ) {
				continue;
			}
			$start = (int) $entity['start'];
			$end   = $start + (int) $entity['length'];

			$this->assertFalse(
				$start < $iban_end && $iban_start < $end,
				sprintf( 'Entity %s overlaps the IBAN — a fragment would leak.', $entity['type'] )
			);
		}
	}

	/**
	 * The whole IBAN must be gone from the sanitised prompt.
	 */
	public function test_full_iban_does_not_survive_in_the_text(): void {
		$iban     = 'DE89370400440532013000';
		$text     = "Aktenzeichen 2 O 145/23, Zahlung an {$iban}.";
		$entities = $this->engine->detect_entities( $text );

		$redacted = $text;
		foreach ( $entities as $entity ) {
			$redacted = str_replace( (string) $entity['value'], '{{REDACTED}}', $redacted );
		}

		$this->assertStringNotContainsString( $iban, $redacted );
		// No readable run of account digits may remain either.
		$this->assertDoesNotMatchRegularExpression( '/[0-9]{6,}/', $redacted );
	}
}
