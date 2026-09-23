<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Regression;

use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Tests\Support\Stack;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the parser differential: ruby-saml verified with one parser and read with another, and the two
 * disagreed on a DOCTYPE (CVE-2025-25291) and on a namespace (CVE-2025-25292). The rule: one parser, one DOM (I-4),
 * a DOCTYPE refused before parsing (I-1), a diagnostic a refusal (I-3).
 */
final class RubySamlParserDifferentialTest extends TestCase
{
    private Loader $loader;

    protected function setUp(): void
    {
        $this->loader = new Loader(Stack::idAttributes());
    }

    /**
     * CVE-2025-25291: a response whose DOCTYPE makes one parser see a different document than the other.
     */
    #[Test]
    public function cve202525291ADoctypeInAResponseIsRefusedBeforeAnyParserSeesIt(): void
    {
        // Given
        $bytes =
            '<!DOCTYPE samlp:Response [<!ENTITY assertion "">]>'
            . '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r">&assertion;</samlp:Response>';

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * CVE-2025-25292: a namespace one parser binds and the other does not; here an unbound prefix on the element the
     * signature reference points at, which libxml reports and the brick refuses.
     */
    #[Test]
    public function cve202525292ANamespaceTheParsersDisagreeOnIsRefusedAtParsing(): void
    {
        // Given
        $bytes = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><saml:Assertion ID="_a"/></samlp:Response>';

        // Then
        $this->expectException(ParserDiagnostic::class);
        $this->expectExceptionMessageIs('libxml reported a diagnostic: error 201, level 2, at line 1, column 99 (I-3).');

        // When
        $this->loader->load($bytes);
    }
}
