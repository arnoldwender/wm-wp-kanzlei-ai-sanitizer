<?php
declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
}
if ( ! defined( 'WM_KANZLEI_PATH' ) ) {
	define( 'WM_KANZLEI_PATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'WM_KANZLEI_VERSION' ) ) {
	define( 'WM_KANZLEI_VERSION', '1.2.2' );
}

require_once dirname( __DIR__ ) . '/includes/Sanitizer/DetectionFailed.php';
require_once dirname( __DIR__ ) . '/includes/Sanitizer/NerEngine.php';
require_once dirname( __DIR__ ) . '/includes/Sanitizer/TokenVault.php';
