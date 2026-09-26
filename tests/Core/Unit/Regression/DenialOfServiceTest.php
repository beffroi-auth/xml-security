<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, denial of service: deep, wide or huge documents, and many namespace declarations that make inclusive
 * canonicalization expensive. The rule: six bounds with defaults and ceilings, the byte bound before parsing,
 * LIBXML_PARSEHUGE never set (I-7).
 */
final class DenialOfServiceTest extends TestCase
{
    /**
     * I-7: each shape is refused with the bound named, or by libxml before the traversal runs.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideShapes')]
    public function aDocumentOverABoundIsRefused(string $fixture, string $exception): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException($exception);

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>}>
     */
    public static function provideShapes(): iterable
    {
        yield 'huge, one byte over maxBytes' => ['hostile/bytes-one-over-max-bytes-refused.xml', LimitExceeded::class];
        yield 'deep, depth 65' => ['hostile/depth-65-refused.xml', LimitExceeded::class];
        yield 'deeper than libxml allows without LIBXML_PARSEHUGE' => [
            'hostile/depth-300-malformed-refused.xml',
            MalformedXml::class,
        ];
        yield 'wide, one element over maxElements' => ['hostile/elements-10001-refused.xml', LimitExceeded::class];
        yield 'one attribute over maxAttributesPerElement' => [
            'hostile/attributes-33-refused.xml',
            LimitExceeded::class,
        ];
        yield 'one declaration over maxNamespaceDeclarations' => [
            'hostile/namespace-declarations-513-refused.xml',
            LimitExceeded::class,
        ];
    }
}
