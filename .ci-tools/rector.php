<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php55\Rector\String_\StringClassNameToClassConstantRector;
use Rector\PHPUnit\CodeQuality\Rector\ClassMethod\AddInstanceofAssertForNullableArgumentRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([
    SetList::DEAD_CODE,
    SetList::CODE_QUALITY,
    SetList::TYPE_DECLARATION,
    LevelSetList::UP_TO_PHP_84,
    PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES,
]);
$builder->withComposerBased(phpunit: true);
$builder->withPhpVersion(PhpVersion::PHP_84);
$builder->withPaths([
    __DIR__ . '/../src',
    __DIR__ . '/../tests',
    __DIR__ . '/../castor.php',
    __DIR__ . '/../.castor',
    __DIR__ . '/rector.php',
]);
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
    // The source guard test lists the banned class names of section 8 as tokens to search for, never to reference:
    // turning 'Dom\XPath' into XPath::class is the very thing the ban catches.
    StringClassNameToClassConstantRector::class,
    // assertNotNull() narrows a nullable node for PHPStan already; the assertInstanceOf() this rule adds after
    // it is one PHPStan then reports as always true.
    AddInstanceofAssertForNullableArgumentRector::class,
]);
$builder->withParallel();
$builder->withImportNames();

return $builder;
