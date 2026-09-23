<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Exception\XmlVersionRefused;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: an XML version other than 1.0 (I-5). A consumer catches the base class when it does not care which rule fired.
 */
final class XmlVersionRefusedTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(XmlVersionRefused::class));
    }
}
