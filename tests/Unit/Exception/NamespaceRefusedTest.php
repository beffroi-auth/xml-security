<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Exception;

use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: a relative namespace URI, a prefixed node without namespace (I-6). A consumer catches the base class when it does not care which rule fired.
 */
final class NamespaceRefusedTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(NamespaceRefused::class));
    }
}
