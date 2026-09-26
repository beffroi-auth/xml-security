<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Libxml;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the XXE family: external entities read files and URLs, entity expansion exhausts memory, an external
 * DTD is fetched. The rule: a DOCTYPE is refused before parsing, so no entity is ever defined (I-1, I-2).
 */
final class XxeFamilyTest extends TestCase
{
    /**
     * I-1: the attack shapes of the XXE family never reach the parser.
     */
    #[Test]
    #[DataProvider('provideXxeShapes')]
    public function theXxeFamilyIsRefusedBeforeTheParserSeesIt(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);
        Libxml::fillBuffer();

        // When
        try {
            new Loader(Stack::idAttributes())->load($bytes);
            static::fail('The DOCTYPE was not refused.');
        } catch (DoctypeRefused $refusal) {
            // Then
            static::assertSame('The input contains a document type declaration (I-1).', $refusal->getMessage());
            static::assertCount(1, Libxml::buffer());
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideXxeShapes(): iterable
    {
        yield 'an external entity reading a file' => ['hostile/doctype-external-entity-file-refused.xml'];
        yield 'an external entity fetching a URL' => ['hostile/doctype-external-entity-http-refused.xml'];
        yield 'a parameter entity fetching a DTD' => ['hostile/doctype-parameter-entity-refused.xml'];
        yield 'an external DTD subset' => ['hostile/doctype-external-subset-refused.xml'];
        yield 'the billion laughs' => ['hostile/doctype-billion-laughs-refused.xml'];
    }
}
