<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\CanonicalXml;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use Beffroi\Xml\Core\Name;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the empty canonical form: xmlseclibs hashed the empty string libxml returned when canonicalization
 * failed (CVE-2025-66578, 8 December 2025). The rule: a false return is an exception and a CanonicalXml cannot hold
 * the empty string (I-13).
 */
final class EmptyCanonicalFormTest extends TestCase
{
    /**
     * CVE-2025-66578: a canonicalization libxml cannot do is a refusal, never a string to hash.
     */
    #[Test]
    public function cve202566578AFailedCanonicalizationIsARefusalNotAString(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('relative', 'x:b'));

        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('libxml could not canonicalize the apex: error 1955 (I-13).');

        // When
        new Canonicalizer()->canonicalize($root, CanonicalizationMethod::Exclusive);
    }

    /**
     * CVE-2025-66578: the empty string cannot become a CanonicalXml, whoever produced it.
     */
    #[Test]
    public function cve202566578TheEmptyStringIsNeverACanonicalForm(): void
    {
        // Then
        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessageIs('The canonical form is empty (I-13).');

        // When
        new CanonicalXml('');
    }
}
