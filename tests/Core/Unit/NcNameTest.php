<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\NcName;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, I-8: Namespaces in XML 1.0 §3, production NCName, over the character classes of XML 1.0 fifth
 * edition §2.3. The IDs of the loader and the references of Dsig are checked with it.
 */
final class NcNameTest extends TestCase
{
    #[Test]
    #[DataProvider('provideNcNames')]
    public function itAcceptsAnNcName(string $value): void
    {
        // When / Then
        static::assertTrue(NcName::is($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNcNames(): iterable
    {
        yield 'an underscore and hexadecimal digits' => ['_a1b2c3'];
        yield 'a GUID after an underscore' => ['_2cac9ed1-b223-4fb8-83bd-03d6f59d682d'];
        yield 'a letter alone' => ['a'];
        yield 'dots and hyphens after the first character' => ['a.b-c'];
        yield 'a start character outside ASCII' => ["\u{E9}t\u{E9}"];
        yield 'a supplementary plane start character' => ["\u{1F600}"];
        yield 'a middle dot after the first character' => ["a\u{B7}b"];
    }

    #[Test]
    #[DataProvider('provideNonNcNames')]
    public function itRefusesWhatIsNotAnNcName(string $value): void
    {
        // When / Then
        static::assertFalse(NcName::is($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNonNcNames(): iterable
    {
        yield 'empty' => [''];
        yield 'a leading digit' => ['1a'];
        yield 'a colon' => ['a:b'];
        yield 'a space' => ['a b'];
        yield 'a leading hyphen' => ['-a'];
        yield 'a leading dot' => ['.a'];
        yield 'an xpointer form' => ['xpointer(/)'];
        yield 'a hash' => ['#a'];
        yield 'a slash' => ['a/b'];
        yield 'a trailing line feed' => ["a\n"];
    }
}
