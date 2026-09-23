<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// The phpqa image ships the slow test detector next to its PHPUnit phar; the extension is loaded from there.
$phpqaPhpunitAutoload = '/tools/.composer/vendor-bin/phpunit/vendor/autoload.php';
if (file_exists($phpqaPhpunitAutoload)) {
    require_once $phpqaPhpunitAutoload;
}
