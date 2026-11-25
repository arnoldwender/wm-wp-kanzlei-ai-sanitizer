<?php
/**
 * A detection pattern could not run; the text was not checked completely.
 *
 * The message is fixed (escaped output rules apply to exception messages); the failing type and the PCRE error
 * are properties.
 *
 * @package WMCyber\Kanzlei
 */

declare(strict_types=1);

namespace WMCyber\Kanzlei\Sanitizer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DetectionFailed extends \RuntimeException {

	public function __construct( public readonly string $type, public readonly int $pcre_error ) {
		parent::__construct( 'A detection pattern failed; nothing was replaced.' );
	}
}
