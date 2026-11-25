<?php
declare(strict_types=1);

namespace WMCyber\Kanzlei\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WMCyber\Kanzlei\Sanitizer\NerEngine;

final class NerEngineTest extends TestCase {
	private NerEngine $engine;

	protected function setUp(): void {
		parent::setUp();
		$this->engine = new NerEngine();
	}

	public function test_detect_entities_aktenzeichen_and_iban(): void {
		$text = 'Im Rechtsstreit 2 O 145/23 überweisen Sie bitte das Honorar an DE89370400440532013000 oder kontaktieren anwalt@kanzlei-mueller.de.';

		$entities = $this->engine->detect_entities( $text );

		$this->assertNotEmpty( $entities );
		$types = array_column( $entities, 'type' );

		$this->assertContains( 'AKTENZEICHEN', $types );
		$this->assertContains( 'IBAN', $types );
		$this->assertContains( 'EMAIL', $types );
	}

	public function test_leading_zero_eleven_digit_phone_becomes_phone_not_steuer_id(): void {
		$entities = $this->engine->detect_entities( 'Tel. 01761234567 oder 03451234567' );

		$this->assertCount( 2, $entities );
		$this->assertSame( 'PHONE', $entities[0]['type'] );
		$this->assertSame( '01761234567', $entities[0]['value'] );
		$this->assertSame( 'PHONE', $entities[1]['type'] );
		$this->assertSame( '03451234567', $entities[1]['value'] );
	}

	public function test_steuer_id_checksum_validation_follows_bzst_mod_11_10(): void {
		$this->assertTrue( NerEngine::steuer_id_checksum_ok( '86095742719' ) );
		$this->assertTrue( NerEngine::steuer_id_checksum_ok( '86 095 742 719' ) );
		$this->assertTrue( NerEngine::steuer_id_checksum_ok( '86-095-742-719' ) );
		$this->assertTrue( NerEngine::steuer_id_checksum_ok( '12113456784' ) );

		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '12345678901' ) );
		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '12345678903' ) );
		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '86095742718' ) );
		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '06095742719' ) );
		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '11123456786' ) );
		$this->assertFalse( NerEngine::steuer_id_checksum_ok( '11223456785' ) );
	}

	public function test_collect_review_warnings_for_steuer_id_and_trailing_name_word(): void {
		$text     = 'Steuer-ID 12 345 678 901; Herr Hans Peter Schmidt Mustermann. Herr Müller Richterin.';
		$entities = $this->engine->detect_entities( $text );
		$warnings = $this->engine->collect_review_warnings( $text, $entities );

		$this->assertCount( 2, $warnings );
		$this->assertSame( 'steuer_id_unverified_checksum', $warnings[0]['code'] );
		$this->assertSame( 'STEUER_ID', $warnings[0]['type'] );
		$this->assertSame( '12 345 678 901', $warnings[0]['span'] );

		$this->assertSame( 'possible_trailing_name_word', $warnings[1]['code'] );
		$this->assertSame( 'PERSON_NAME', $warnings[1]['type'] );
		$this->assertSame( 'Mustermann', $warnings[1]['span'] );
	}
}
