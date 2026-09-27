<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SignedInfo;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, D-2, D-4, D-5, D-9: the SignedInfo read strictly, its exclusive method with an optional prefix list,
 * its signature method, its one reference.
 */
final class SignedInfoTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    #[Test]
    public function itReadsTheSignedInfoOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $element = $this->signedInfoOf($document->elementById('_assertion-d4e5f6'));

        // When
        $signedInfo = SignedInfo::of($element);

        // Then
        static::assertSame($element, $signedInfo->element);
        static::assertSame(CanonicalizationMethod::Exclusive, $signedInfo->canonicalizationMethod);
        static::assertSame([], $signedInfo->inclusiveNamespaces->prefixes);
        static::assertSame(SignatureAlgorithm::RsaSha256, $signedInfo->signatureMethod);
        static::assertSame('_assertion-d4e5f6', $signedInfo->reference->id);
    }

    /**
     * Section 5.3: the PrefixList of the CanonicalizationMethod and the one of the transform are read apart.
     */
    #[Test]
    public function itReadsThePrefixListsOfTheMethodAndOfTheTransform(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/prefixlist-loads.xml');

        // When
        $signedInfo = SignedInfo::of($this->signedInfoOf($document->elementById('_assertion-d4e5f6')));

        // Then
        static::assertSame(['saml'], $signedInfo->inclusiveNamespaces->prefixes);
        static::assertSame(['#default', 'saml', 'ds'], $signedInfo->reference->inclusiveNamespaces->prefixes);
    }

    /**
     * Section 5.3, D-4: exclusive canonicalization with comments, in the method and in the transform.
     */
    #[Test]
    public function itReadsAnExclusiveCanonicalizationWithComments(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/canonicalization-with-comments-loads.xml');

        // When
        $signedInfo = SignedInfo::of($this->signedInfoOf($document->elementById('_assertion-d4e5f6')));

        // Then
        static::assertSame(CanonicalizationMethod::ExclusiveWithComments, $signedInfo->canonicalizationMethod);
        static::assertSame(CanonicalizationMethod::ExclusiveWithComments, $signedInfo->reference->canonicalization);
    }

    /**
     * §9.2 row 22, D-4: an inclusive canonicalization method.
     */
    #[Test]
    public function itRefusesAnInclusiveCanonicalizationMethod(): void
    {
        // Given
        $document = Loaded::fixture('hostile/canonicalization-inclusive-refused.xml');
        $element = $this->signedInfoOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('The canonicalization method is not exclusive (D-4).');

        // When
        SignedInfo::of($element);
    }

    /**
     * §9.2 row 19, D-9: an HMACOutputLength under a SignatureMethod, even an RSA one.
     */
    #[Test]
    public function itRefusesAChildUnderTheSignatureMethod(): void
    {
        // Given
        $document = Loaded::fixture('hostile/signature-method-with-a-child-refused.xml');
        $element = $this->signedInfoOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A SignatureMethod holds no child (D-9).');

        // When
        SignedInfo::of($element);
    }

    private function signedInfoOf(Element $signed): Element
    {
        return Children::one(
            Children::one($signed, new Name(self::DSIG, 'Signature')),
            new Name(self::DSIG, 'SignedInfo'),
        );
    }
}
