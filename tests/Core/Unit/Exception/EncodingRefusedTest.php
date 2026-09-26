<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: not UTF-8, a UTF-16 or UTF-32 byte order mark, a declared encoding other than UTF-8 (I-5). A consumer catches the base class when it does not care which rule fired.
 */
final class EncodingRefusedTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(EncodingRefused::class));
    }
}
