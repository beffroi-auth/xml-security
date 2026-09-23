<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Section 5.7: a RefusedXml is input the brick refuses, a runtime condition, never a programming error.
 */
final class RefusedXmlTest extends TestCase
{
    #[Test]
    public function itIsARuntimeException(): void
    {
        // When / Then
        static::assertContains(RuntimeException::class, class_parents(RefusedXml::class));
    }
}
