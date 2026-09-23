<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Beffroi\Xml\Core\Tests\Support\Stack;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, comment-split text: a comment inside a NameID splits its text node, and several implementations read
 * only the first half (Duo Labs, 27 February 2018: CVE-2017-11427, CVE-2017-11428, CVE-2017-11429, CVE-2017-11430,
 * CVE-2018-0489, CVE-2018-7340). The rule: Text::of() concatenates every text and CDATA child (I-12).
 */
final class CommentSplitTextTest extends TestCase
{
    private const string RESPONSE =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
            . '<saml:Assertion ID="_a"><saml:Subject><saml:NameID>user@example.com<!---->.evil.com</saml:NameID></saml:Subject></saml:Assertion>'
            . '</samlp:Response>';

    /**
     * CVE-2017-11428, CVE-2018-0489: the NameID read is the whole text, the value the signature covers.
     */
    #[Test]
    public function cve201711428TheNameIdReadIsTheWholeTextAroundTheComment(): void
    {
        // Given
        $document = Loaded::document(self::RESPONSE);
        $subject = Children::one($document->elementById('_a'), new Name(Stack::SAML_ASSERTION, 'Subject'));

        // When
        $nameId = Text::of(Children::one($subject, new Name(Stack::SAML_ASSERTION, 'NameID')));

        // Then
        static::assertSame('user@example.com.evil.com', $nameId);
    }

    /**
     * CVE-2018-0489: the canonical form without comments, the one signed, carries the whole text too, so what is
     * verified is what is read.
     */
    #[Test]
    public function cve20180489TheCanonicalFormSignedCarriesTheWholeText(): void
    {
        // Given
        $document = Loaded::document(self::RESPONSE);

        // When
        $canonical = new Canonicalizer()->canonicalize($document->elementById('_a'), CanonicalizationMethod::Exclusive);

        // Then
        static::assertStringContainsString('<saml:NameID>user@example.com.evil.com</saml:NameID>', $canonical->bytes);
    }
}
