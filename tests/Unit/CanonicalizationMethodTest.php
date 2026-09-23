<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Exception\UnknownCanonicalizationMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4: the four methods the protocol fixes, their URIs and their two flags.
 */
final class CanonicalizationMethodTest extends TestCase
{
    /**
     * Section 9.1: each case round-trips through fromUri().
     */
    #[Test]
    #[DataProvider('provideMethods')]
    public function itRoundTripsThroughItsUri(
        CanonicalizationMethod $method,
        string $uri,
        bool $exclusive,
        bool $withComments,
    ): void {
        // When / Then
        static::assertSame($method, CanonicalizationMethod::fromUri($uri));
        static::assertSame($uri, $method->value);
    }

    /**
     * Section 5.4: the mapping of a method to the two flags of C14N().
     */
    #[Test]
    #[DataProvider('provideMethods')]
    public function itMapsToTheExclusiveAndCommentsFlags(
        CanonicalizationMethod $method,
        string $uri,
        bool $exclusive,
        bool $withComments,
    ): void {
        // When / Then
        static::assertSame($exclusive, $method->isExclusive());
        static::assertSame($withComments, $method->withComments());
    }

    /**
     * @return iterable<string, array{CanonicalizationMethod, string, bool, bool}>
     */
    public static function provideMethods(): iterable
    {
        yield 'inclusive' => [
            CanonicalizationMethod::Inclusive,
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
            false,
            false,
        ];
        yield 'inclusive with comments' => [
            CanonicalizationMethod::InclusiveWithComments,
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
            false,
            true,
        ];
        yield 'exclusive' => [
            CanonicalizationMethod::Exclusive,
            'http://www.w3.org/2001/10/xml-exc-c14n#',
            true,
            false,
        ];
        yield 'exclusive with comments' => [
            CanonicalizationMethod::ExclusiveWithComments,
            'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
            true,
            true,
        ];
    }

    /**
     * Section 9.1, section 11: Canonical XML 1.1 is not reachable from PHP and is refused like any unknown URI; the
     * message carries no input (I-16).
     */
    #[Test]
    #[DataProvider('provideUnknownUris')]
    public function itRefusesAnUnknownUri(string $uri): void
    {
        // Then
        $this->expectException(UnknownCanonicalizationMethod::class);
        $this->expectExceptionMessageIs('The canonicalization method is not one of the four the brick renders (section 5.4).');

        // When
        CanonicalizationMethod::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnknownUris(): iterable
    {
        yield 'Canonical XML 1.1' => ['http://www.w3.org/2006/12/xml-c14n11'];
        yield 'Canonical XML 1.1 with comments' => ['http://www.w3.org/2006/12/xml-c14n11#WithComments'];
        yield 'Canonical XML 2.0' => ['http://www.w3.org/2010/xml-c14n2'];
        yield 'a case variant of a known URI' => ['HTTP://www.w3.org/2001/10/xml-exc-c14n#'];
        yield 'a known URI with a trailing character' => ['http://www.w3.org/2001/10/xml-exc-c14n#x'];
        yield 'empty' => [''];
    }
}
