<?php
/**
 * Pattern detector for seven kinds of values in German legal text.
 *
 * It is regular expressions, not named-entity recognition with a model: what the patterns do not describe is
 * not found. Not detected, measured on 2026-09-15: names without one of the trigger words ("Max Mustermann"),
 * addresses, dates of birth, Steuernummer, USt-IdNr, social security, health insurance and ID card numbers,
 * register numbers, number plates, health data. Callers must treat the output as a reduction, never as a
 * guarantee that a text is free of personal data.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Sanitizer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NerEngine {

	/** Every type the engine can report. */
	public const TYPES = [ 'AKTENZEICHEN', 'IBAN', 'EMAIL', 'STEUER_ID', 'PHONE', 'PERSON_NAME', 'GELDBETRAG' ];

	/** Words that introduce a name ("Herrn Müller", "Mandantin Yilmaz", "dem Beklagten Fischer"). */
	private const NAME_TRIGGERS = 'Herrn?|Frau|Rechtsanwältin|Rechtsanwalt|RAin|RA|Mandantin|Mandanten|Mandant|Zeugin|Zeugen|Zeuge|Beklagten|Beklagter|Beklagte|Klägerin|Klägers|Kläger|Patientin|Patienten|Patient|Dr\.|Prof\.';

	/** Role nouns that follow a trigger without being a name ("Frau Richterin", "Herr Vorsitzender"). */
	private const NOT_A_NAME = 'Richterin|Richter|Vorsitzende|Vorsitzender|Kollegin|Kollege|Präsidentin|Präsident|Rechtsanwältin|Rechtsanwalt|Staatsanwältin|Staatsanwalt|Anwältin|Anwalt|Doktor|Professorin|Professor|Notarin|Notar';

	/**
	 * Find the values of the requested types.
	 *
	 * Fails closed: text that is not valid UTF-8, or a pattern that errors, throws instead of returning what the
	 * remaining patterns found. Until 2026-09-15 one Windows-1252 byte made every `/u` pattern return nothing and
	 * the text counted as clean, with only the IBAN detected.
	 *
	 * @param string            $text  Raw text.
	 * @param list<string>|null $types Types to report; null for all.
	 * @return list<array{type: string, value: string, start: int, length: int}> Non-overlapping, by position.
	 * @throws \InvalidArgumentException When the text is not valid UTF-8.
	 * @throws DetectionFailed When a pattern fails (a RuntimeException).
	 */
	public function detect_entities( string $text, ?array $types = null ): array {
		if ( 1 !== preg_match( '//u', $text ) ) {
			if ( PREG_BAD_UTF8_ERROR === preg_last_error() ) {
				throw new \InvalidArgumentException( 'The text is not valid UTF-8; nothing was detected.' );
			}
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a type code and a PCRE error number; the message is fixed.
			throw new DetectionFailed( 'TEXT', preg_last_error() );
		}
		$want = static fn( string $type ): bool => null === $types || in_array( $type, $types, true );

		$entities = [];

		// 1. Court file numbers: chamber (digits or a Roman numeral), register of 1-4 letters starting with a capital
		// (O, C, ZR, BvR, StR, AZR), number / year. "VI ZR 244/20" and "1 BvR 102/22" are the documented examples;
		// until 2026-09-15 the register had to be one capital plus lowercase letters, so neither matched.
		if ( $want( 'AKTENZEICHEN' ) ) {
			$this->collect( $entities, 'AKTENZEICHEN', '/(?<![\w\/])(?:\d{1,3}|[IVX]{1,5})\s+[A-Z][A-Za-z]{0,3}(?:\s+[A-Z][A-Za-z]{0,3})?\s+\d{1,5}\/\d{2,4}(?![\w\/])/u', $text );
		}

		// 2. IBAN (ISO 13616): 2 letters, 2 check digits, 11-30 letters or digits, spaced or hyphenated, any case.
		if ( $want( 'IBAN' ) ) {
			$this->collect_ibans( $entities, $text );
		}

		// 3. E-mail addresses.
		if ( $want( 'EMAIL' ) ) {
			$this->collect( $entities, 'EMAIL', '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/', $text );
		}

		// 4. Steuer-ID: 11 digits (first digit 1-9 per § 139b AO, so leading-zero phone numbers are not claimed), optionally grouped 2-3-3-3.
		if ( $want( 'STEUER_ID' ) ) {
			$this->collect( $entities, 'STEUER_ID', '/(?<![\w\/.,-])[1-9]\d\s?\d{3}\s?\d{3}\s?\d{3}(?![\w\/,-]|\.\d)/', $text );
		}

		// 5. German phone numbers: +49 (also "+49 345 …" and "+49 (0)345 …"), 0049 or a leading 0. The look-behind keeps
		// the pattern out of longer digit runs: until 2026-09-15 it claimed the middle of lowercase or hyphenated
		// IBANs and 13-digit tax numbers and left readable fragments on both sides.
		if ( $want( 'PHONE' ) ) {
			$this->collect( $entities, 'PHONE', '/(?<![\w+])(?:\+49\s?(?:\(0\)\s?)?|0049\s?|0)[1-9][0-9\s\/\-\(\)]{5,15}[0-9](?!\d)/', $text );
		}

		// 6. Names after a trigger word, with academic titles, a particle and up to three (hyphenated) name words.
		// Until 2026-09-15 "Frau Dr. Schneider" became "Frau Dr" and "Herr Hans-Peter Schmidt" "Herr Hans".
		if ( $want( 'PERSON_NAME' ) ) {
			$name_word = '[A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)?';
			$pattern   = '/(?<![\p{L}])(?:' . self::NAME_TRIGGERS . ')\s+(?:(?:Dr\.|Prof\.)\s*)*(?:(?:von|van|de|zu|vom|zum)\s+)?(?!(?:' . self::NOT_A_NAME . ')(?![\p{L}]))' . $name_word . '(?:\s+(?!(?:' . self::NOT_A_NAME . ')(?![\p{L}]))' . $name_word . '){0,2}/u';
			$this->collect( $entities, 'PERSON_NAME', $pattern, $text );
		}

		// 7. Amounts with the currency before or after, with or without thousands dots. Until 2026-09-15 a trailing
		// \b after "€" or "$" required a letter or digit to follow, so "50.000,00 €." never matched.
		if ( $want( 'GELDBETRAG' ) ) {
			$number = '(?:\d{1,3}(?:\.\d{3})+|\d+)(?:,\d{2})?';
			$this->collect( $entities, 'GELDBETRAG', '/(?:(?:EUR|USD|€|\$)\s?' . $number . '(?![\d.,]*\d))|(?:(?<![\d.,])' . $number . '\s?(?:EUR\b|Euro\b|USD\b|€|\$))/u', $text );
		}

		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filters additional custom regex entity patterns (`TYPE => '/pattern/u'`) evaluated during detection.
			 *
			 * @param array<string, string> $custom_patterns Map of uppercase entity type code (`A-Z_`) to PCRE pattern.
			 * @param string                $text            Input text being scanned.
			 * @param list<string>|null     $types           Requested entity types, or null for all.
			 */
			$custom_patterns = apply_filters( 'wm_kanzlei_entity_patterns', [], $text, $types );
			if ( is_array( $custom_patterns ) ) {
				foreach ( $custom_patterns as $custom_type => $custom_pattern ) {
					$normalized = is_string( $custom_type ) ? strtoupper( trim( $custom_type ) ) : '';
					if ( '' !== $normalized && 1 === preg_match( '/^[A-Z_]+$/', $normalized ) && is_string( $custom_pattern ) && '' !== $custom_pattern && $want( $normalized ) ) {
						$this->collect( $entities, $normalized, $custom_pattern, $text );
					}
				}
			}
		}

		$entities = self::resolve_overlaps( $entities );

		// A surname found after a trigger is replaced wherever it appears on its own: until 2026-09-15 "Herr Müller
		// kündigte. Müller verlangt …" sent the second "Müller" in clear text.
		if ( $want( 'PERSON_NAME' ) ) {
			$entities = self::resolve_overlaps( array_merge( $entities, $this->repeated_surnames( $entities, $text ) ) );
		}

		return $entities;
	}

	/**
	 * @param list<array{type: string, value: string, start: int, length: int}> $entities
	 */
	private function collect( array &$entities, string $type, string $pattern, string $text ): void {
		$found = preg_match_all( $pattern, $text, $matches, PREG_OFFSET_CAPTURE );
		if ( false === $found ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a type code and a PCRE error number; the message is fixed.
			throw new DetectionFailed( $type, preg_last_error() );
		}
		foreach ( $matches[0] as [ $value, $offset ] ) {
			$trimmed = rtrim( $value );
			$entities[] = [
				'type'   => $type,
				'value'  => $trimmed,
				'start'  => $offset,
				'length' => strlen( $trimmed ),
			];
		}
	}

	/**
	 * IBAN candidates, cut to the longest prefix whose ISO 7064 mod-97 check passes. A candidate that never passes
	 * (a typo, a made-up sample) is still redacted, without trailing words: "DE89370400440532013000 BITTE BIS"
	 * used to be captured whole because letters are valid IBAN characters.
	 *
	 * @param list<array{type: string, value: string, start: int, length: int}> $entities
	 */
	private function collect_ibans( array &$entities, string $text ): void {
		$found = preg_match_all( '/(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}(?:[ -]?[A-Za-z0-9]){11,30}/', $text, $matches, PREG_OFFSET_CAPTURE );
		if ( false === $found ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a type code and a PCRE error number; the message is fixed.
			throw new DetectionFailed( 'IBAN', preg_last_error() );
		}
		foreach ( $matches[0] as [ $candidate, $offset ] ) {
			$value = self::longest_valid_iban( $candidate );
			if ( null === $value ) {
				$value = (string) preg_replace( '/(?:[ -][A-Za-z]+)+$/', '', $candidate );
				if ( strlen( (string) preg_replace( '/[ -]/', '', $value ) ) < 15 ) {
					continue;
				}
			}
			$entities[] = [ 'type' => 'IBAN', 'value' => $value, 'start' => $offset, 'length' => strlen( $value ) ];
		}
	}

	/**
	 * The longest prefix of the candidate that passes mod-97 and ends at a group boundary (before a space, a hyphen
	 * or the end), or null. Only group boundaries count: a prefix ending inside a following word ("…606 b" of
	 * "…606 bis") passes the check by chance once in 97 times and would swallow the word. For the same reason a
	 * prefix whose last group is letters only (a word after the IBAN) is taken only when no prefix ending in a group
	 * with a digit passes: measured on 2026-09-15, "FR1420041010050500013M02606 bis" passes mod-97 as a whole.
	 */
	public static function longest_valid_iban( string $candidate ): ?string {
		$n    = strlen( $candidate );
		$ends = [];
		for ( $i = 0; $i < $n; $i++ ) {
			$is_char  = ' ' !== $candidate[ $i ] && '-' !== $candidate[ $i ];
			$boundary = $i + 1 === $n || ' ' === $candidate[ $i + 1 ] || '-' === $candidate[ $i + 1 ];
			if ( $is_char && $boundary ) {
				$ends[] = $i + 1;
			}
		}
		$word_ending = null;
		foreach ( array_reverse( $ends ) as $end ) {
			$prefix = substr( $candidate, 0, $end );
			if ( strlen( (string) preg_replace( '/[ -]/', '', $prefix ) ) < 15 || ! self::iban_checksum_ok( $prefix ) ) {
				continue;
			}
			$groups     = preg_split( '/[ -]/', $prefix ) ?: [];
			$last_group = (string) end( $groups );
			if ( count( $groups ) > 1 && 1 === preg_match( '/^[A-Za-z]+$/', $last_group ) ) {
				$word_ending ??= $prefix;
				continue;
			}
			return $prefix;
		}
		return $word_ending;
	}

	/** ISO 13616 / ISO 7064 mod-97-10 check of an IBAN written with or without separators. */
	public static function iban_checksum_ok( string $iban ): bool {
		$compact = strtoupper( (string) preg_replace( '/[ -]/', '', $iban ) );
		if ( 1 !== preg_match( '/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/', $compact ) ) {
			return false;
		}
		$rearranged = substr( $compact, 4 ) . substr( $compact, 0, 4 );
		$remainder  = 0;
		foreach ( str_split( $rearranged ) as $char ) {
			$digits = ctype_alpha( $char ) ? (string) ( ord( $char ) - 55 ) : $char;
			foreach ( str_split( $digits ) as $digit ) {
				$remainder = ( $remainder * 10 + (int) $digit ) % 97;
			}
		}
		return 1 === $remainder;
	}

	/**
	 * Official BZSt § 139b AO / ISO/IEC 7064, MOD 11,10 check for an 11-digit German Steuer-ID.
	 */
	public static function steuer_id_checksum_ok( string $candidate ): bool {
		$compact = (string) preg_replace( '/[\s-]+/', '', $candidate );
		if ( 1 !== preg_match( '/^[1-9]\d{10}$/', $compact ) ) {
			return false;
		}

		$body = substr( $compact, 0, 10 );
		if ( 1 === preg_match( '/(\d)\1\1/', $body ) ) {
			return false;
		}

		$repeated_digits = 0;
		foreach ( count_chars( $body, 1 ) as $count ) {
			if ( $count > 3 ) {
				return false;
			}
			if ( $count > 1 ) {
				++$repeated_digits;
			}
		}
		if ( 1 !== $repeated_digits ) {
			return false;
		}

		$product = 10;
		for ( $i = 0; $i < 10; $i++ ) {
			$sum = ( (int) $compact[ $i ] + $product ) % 10;
			if ( 0 === $sum ) {
				$sum = 10;
			}
			$product = ( $sum * 2 ) % 11;
		}
		$check = 11 - $product;
		if ( 10 === $check ) {
			$check = 0;
		}

		return $check === (int) $compact[10];
	}

	/**
	 * Collect non-blocking review warnings for an attorney or reviewer:
	 *  - `steuer_id_unverified_checksum`: any `STEUER_ID` candidate that fails the § 139b AO Mod 11,10 check
	 *    (still redacted fail-safe as `STEUER_ID`, warning to check whether it is a typo or reference number);
	 *  - `possible_trailing_name_word`: any `PERSON_NAME` entity immediately followed by whitespace and an
	 *    unredacted capitalised German word not in `NOT_A_NAME` and not overlapping another entity.
	 *
	 * @param string                                                                   $text     Raw text.
	 * @param array<int, array{type: string, value: string, start: int, length: int}> $entities Detected entities.
	 * @return list<array{code: string, type: string, span: string, message: string}>
	 */
	public function collect_review_warnings( string $text, array $entities ): array {
		$warnings   = [];
		$not_a_name = explode( '|', self::NOT_A_NAME );
		$text_len   = strlen( $text );

		foreach ( $entities as $entity ) {
			$type  = (string) ( $entity['type'] ?? '' );
			$value = (string) ( $entity['value'] ?? '' );

			if ( 'STEUER_ID' === $type && '' !== $value && ! self::steuer_id_checksum_ok( $value ) ) {
				$warnings[] = [
					'code'    => 'steuer_id_unverified_checksum',
					'type'    => 'STEUER_ID',
					'span'    => $value,
					'message' => sprintf(
						'The 11-digit candidate "%s" did not pass the § 139b AO Mod 11,10 check digit validation (still redacted as STEUER_ID); please verify whether it is a typo or another reference number.',
						$value
					),
				];
				continue;
			}

			if ( 'PERSON_NAME' !== $type ) {
				continue;
			}

			$end = (int) ( $entity['start'] ?? 0 ) + (int) ( $entity['length'] ?? 0 );
			if ( $end < 0 || $end >= $text_len ) {
				continue;
			}

			$tail = substr( $text, $end );
			if ( 1 !== preg_match( '/^\s+([A-ZÄÖÜ][a-zäöüß]{2,})(?![\p{L}])/u', $tail, $match, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}

			$word = $match[1][0];
			if ( in_array( $word, $not_a_name, true ) ) {
				continue;
			}

			$word_start = $end + (int) $match[1][1];
			$word_end   = $word_start + strlen( $word );
			$overlaps   = false;
			foreach ( $entities as $other ) {
				$o_start = (int) ( $other['start'] ?? 0 );
				$o_end   = $o_start + (int) ( $other['length'] ?? 0 );
				if ( $word_start < $o_end && $o_start < $word_end ) {
					$overlaps = true;
					break;
				}
			}
			if ( $overlaps ) {
				continue;
			}

			$warnings[] = [
				'code'    => 'possible_trailing_name_word',
				'type'    => 'PERSON_NAME',
				'span'    => $word,
				'message' => sprintf(
					'The unredacted capitalised word "%s" immediately follows the detected PERSON_NAME "%s"; please verify whether it is part of the name.',
					$word,
					$value
				),
			];
		}

		return $warnings;
	}

	/**
	 * Bare occurrences of surnames that were found after a trigger word.
	 *
	 * @param list<array{type: string, value: string, start: int, length: int}> $entities
	 * @return list<array{type: string, value: string, start: int, length: int}>
	 */
	private function repeated_surnames( array $entities, string $text ): array {
		$extra = [];
		$seen  = [];
		foreach ( $entities as $entity ) {
			if ( 'PERSON_NAME' !== $entity['type'] ) {
				continue;
			}
			$words   = preg_split( '/\s+/u', $entity['value'] ) ?: [];
			$surname = (string) end( $words );
			if ( mb_strlen( $surname ) < 3 || isset( $seen[ $surname ] ) || 1 !== preg_match( '/^[A-ZÄÖÜ]/u', $surname ) ) {
				continue;
			}
			$seen[ $surname ] = true;
			$found            = preg_match_all( '/(?<![\p{L}-])' . preg_quote( $surname, '/' ) . '(?![\p{L}-])/u', $text, $matches, PREG_OFFSET_CAPTURE );
			if ( false === $found ) {
				// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a type code and a PCRE error number; the message is fixed.
				throw new DetectionFailed( 'PERSON_NAME', preg_last_error() );
			}
			foreach ( $matches[0] as [ $value, $offset ] ) {
				$extra[] = [ 'type' => 'PERSON_NAME', 'value' => $value, 'start' => $offset, 'length' => strlen( $value ) ];
			}
		}
		return $extra;
	}

	/**
	 * Drop entities that overlap a higher-priority match.
	 *
	 * Without this, a single span can be claimed by two patterns. An IBAN partially consumed by
	 * the phone pattern is the dangerous case: the vault tokenises the fragment, the remainder
	 * of the account number is passed through untouched, and the prompt leaves the building with
	 * readable banking data in it.
	 *
	 * Priority is by specificity, then by match length.
	 *
	 * @param array $entities Detected entities.
	 * @return array Non-overlapping entities, ordered by position.
	 */
	private static function resolve_overlaps( array $entities ): array {
		$priority = array(
			'IBAN'          => 100,
			'STEUER_ID'     => 90,
			'EMAIL'         => 80,
			'AKTENZEICHEN'  => 70,
			'GELDBETRAG'    => 60,
			'PERSON_NAME'   => 50,
			'PHONE'         => 40,
		);

		usort(
			$entities,
			static function ( $a, $b ) use ( $priority ) {
				$pa = $priority[ $a['type'] ] ?? 0;
				$pb = $priority[ $b['type'] ] ?? 0;
				if ( $pa !== $pb ) {
					return $pb <=> $pa;
				}
				return $b['length'] <=> $a['length'];
			}
		);

		$kept = array();
		foreach ( $entities as $candidate ) {
			$c_start = (int) $candidate['start'];
			$c_end   = $c_start + (int) $candidate['length'];

			$overlaps = false;
			foreach ( $kept as $accepted ) {
				$a_start = (int) $accepted['start'];
				$a_end   = $a_start + (int) $accepted['length'];
				if ( $c_start < $a_end && $a_start < $c_end ) {
					$overlaps = true;
					break;
				}
			}

			if ( ! $overlaps ) {
				$kept[] = $candidate;
			}
		}

		usort( $kept, static fn( $a, $b ) => $a['start'] <=> $b['start'] );

		return $kept;
	}
}
