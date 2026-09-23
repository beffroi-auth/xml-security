<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Regression;

use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Tests\Support\Fixtures;
use Beffroi\Xml\Core\Tests\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, what libxml parses and only reports: an unbound prefix, an empty prefixed namespace, the xml or xmlns
 * prefix misused, XML 1.1. The rule: any diagnostic, whatever its level, refuses the document (I-3).
 */
final class ParserDiagnosticsTest extends TestCase
{
    /**
     * I-3: every shape libxml parses with a diagnostic is refused, the level notwithstanding.
     */
    #[Test]
    #[DataProvider('provideDiagnosticShapes')]
    public function whatLibxmlOnlyReportsIsRefused(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(ParserDiagnostic::class);

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDiagnosticShapes(): iterable
    {
        yield 'unbound prefix on an element' => ['hostile/unbound-prefix-element-refused.xml'];
        yield 'unbound prefix on an attribute' => ['hostile/unbound-prefix-attribute-refused.xml'];
        yield 'empty prefixed namespace' => ['hostile/xmlns-prefix-empty-refused.xml'];
        yield 'xml prefix rebound' => ['hostile/xmlns-xml-rebound-refused.xml'];
        yield 'xmlns namespace name reused' => ['hostile/xmlns-namespace-reused-refused.xml'];
        yield 'XML 1.1, a level-1 warning' => ['hostile/xml-version-1-1-refused.xml'];
    }
}
