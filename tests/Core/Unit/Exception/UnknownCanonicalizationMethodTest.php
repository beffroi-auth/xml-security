<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Exception\UnknownCanonicalizationMethod;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: a canonicalization URI that is none of the four (section 5.4). A consumer catches the base class when it does not care which rule fired.
 */
final class UnknownCanonicalizationMethodTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(UnknownCanonicalizationMethod::class));
    }
}
