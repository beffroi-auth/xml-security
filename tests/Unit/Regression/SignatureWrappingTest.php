<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit\Regression;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Beffroi\Xml\Core\Tests\Support\Stack;
use Beffroi\Xml\Core\Text;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 3, signature wrapping: the signed element is moved where the verifier does not look, and an unsigned one
 * is put where the consumer reads ("On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012, eleven of
 * fourteen frameworks; CVE-2026-63182 in 2026). The rules: one ID space and no duplicate (I-8), navigation by direct
 * children only (I-11), and the element a consumer receives is the re-parse of the canonical bytes that were hashed
 * (section 6.6).
 */
final class SignatureWrappingTest extends TestCase
{
    private const string RESPONSE =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
            . '<samlp:Extensions><saml:Assertion ID="%s"><saml:Subject><saml:NameID>signed@example.org</saml:NameID></saml:Subject></saml:Assertion></samlp:Extensions>'
            . '<saml:Assertion ID="%s"><saml:Subject><saml:NameID>attacker@example.org</saml:NameID></saml:Subject></saml:Assertion>'
            . '</samlp:Response>';

    /**
     * On Breaking SAML, 2012: the evil assertion carries the ID the signature reference points at; the document is
     * refused as a whole, and getElementById()'s silent first match never happens.
     */
    #[Test]
    public function onBreakingSaml2012TwoAssertionsSharingTheSignedIdRefuseTheDocument(): void
    {
        // Given
        $bytes = sprintf(self::RESPONSE, '_signed', '_signed');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * On Breaking SAML, 2012: with distinct IDs, the assertion wrapped inside samlp:Extensions is not a child of the
     * response, and the one the consumer navigates to is the direct child, whose text is what it is.
     */
    #[Test]
    public function onBreakingSaml2012AWrappedAssertionIsNotAChildOfTheResponse(): void
    {
        // Given
        $document = Loaded::document(sprintf(self::RESPONSE, '_signed', '_evil'));

        // When
        $assertion = Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion'));

        // Then
        static::assertSame('_evil', $assertion->getAttributeNS(null, 'ID'));
        static::assertSame('_signed', $document->elementById('_signed')->getAttributeNS(null, 'ID'));
    }

    /**
     * CVE-2026-63182, section 6.6: what a verifier hands to the consumer is the re-parse of the canonical bytes it
     * hashed, one root, no wrapper, no sibling, no second assertion.
     */
    #[Test]
    public function cve202663182TheElementReceivedIsTheReparseOfTheBytesHashed(): void
    {
        // Given
        $document = Loaded::document(sprintf(self::RESPONSE, '_signed', '_evil'));
        $signed = $document->elementById('_signed');

        // When
        $hashed = new Canonicalizer()->canonicalize($signed, CanonicalizationMethod::Exclusive);
        $received = Loaded::document($hashed->bytes);

        // Then
        $root = $received->root();
        static::assertSame('Assertion', $root->localName);
        static::assertSame('_signed', $root->getAttributeNS(null, 'ID'));
        static::assertNull($root->parentElement);
        static::assertSame([], Children::named($root, new Name(Stack::SAML_PROTOCOL, 'Extensions')));
        static::assertFalse($received->hasId('_evil'));
        $nameId = Children::one(
            Children::one($root, new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('signed@example.org', Text::of($nameId));
    }
}
