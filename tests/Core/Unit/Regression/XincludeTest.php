<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, XInclude and network access during parsing: libxml features one flag away. The rule: LIBXML_XINCLUDE
 * is never set, LIBXML_NONET always is (I-2), and xinclude() is never called (section 8).
 */
final class XincludeTest extends TestCase
{
    /**
     * I-2: an xi:include element pointing at a local file is an ordinary element whose text is empty.
     */
    #[Test]
    public function anXincludeElementPullsNothingIn(): void
    {
        // Given
        $document = Loaded::fixture('hostile/xinclude-element-loads.xml');

        // When
        $include = Children::one($document->root(), new Name('http://www.w3.org/2001/XInclude', 'include'));

        // Then
        static::assertSame('', Text::of($include));
        static::assertSame('file:///etc/hostname', $include->getAttributeNS(null, 'href'));
    }
}
