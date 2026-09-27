<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Exception\SerializationFailed;
use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Signer;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Built;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use Beffroi\Xml\Tests\Dsig\Support\RecordingKey;
use Dom\Element;
use Dom\XMLDocument;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function str_starts_with;
use function substr;

/**
 * Section 6.2, D-12: signing on the loaded form of what was built, the Signature after the child the consumer
 * names, verified by the verifier of this namespace and, byte for byte, by what xmlsec1 verified once
 * (tests/Dsig/Fixture/behaviour/README.md).
 */
final class SignerTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private Signer $signer;

    private Verifier $verifier;

    private PrivateKey $key;

    private VerificationKeys $trusted;

    private Name $issuer;

    protected function setUp(): void
    {
        $loader = new Loader(Stack::idAttributes());
        $this->signer = new Signer($loader);
        $this->verifier = new Verifier($loader);
        $this->key = PrivateKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
        $this->trusted = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);
        $this->issuer = new Name(Stack::SAML_ASSERTION, 'Issuer');
    }

    /**
     * §9.3 row 4: the assertion of a built response signed after its Issuer; the bytes are those xmlsec1 verified,
     * and the verifier verifies them after a load.
     */
    #[Test]
    public function itSignsTheAssertionOfABuiltResponseAfterItsIssuer(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');

        // When
        $signed = $this->signer->sign(
            $document,
            Built::ASSERTION_ID,
            $this->key,
            SignatureAlgorithm::RsaSha256,
            $this->issuer,
            $certificate,
        );

        // Then
        $bytes = new Serializer()->serialize($signed);
        static::assertSame(Fixtures::bytes('behaviour/signed-by-the-signer-assertion-rsa-sha256.xml'), $bytes);
        $assertion = $signed->elementById(Built::ASSERTION_ID);
        $children = Children::all($assertion);
        static::assertSame('Issuer', $children[0]->localName);
        static::assertSame('Signature', $children[1]->localName);
        static::assertSame('ds', $children[1]->prefix);
        $loaded = Loaded::document($bytes);
        $verified = $this->verifier->verify($loaded->elementById(Built::ASSERTION_ID), $this->trusted);
        static::assertSame('Assertion', $verified->document->root()->localName);
    }

    /**
     * §9.3 row 5: sign() then sign() on the returned document, the assertion then the response; both verify, and
     * the response's canonical bytes hold the assertion's Signature. The bytes are those xmlsec1 verified.
     */
    #[Test]
    public function itSignsTheResponseOverTheSignedAssertion(): void
    {
        // Given
        $once = $this->signer->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            $this->key,
            SignatureAlgorithm::RsaSha256,
            $this->issuer,
            Fixtures::bytes('keys/test-signing-certificate.pem'),
        );

        // When
        $twice = $this->signer->sign(
            $once,
            Built::RESPONSE_ID,
            $this->key,
            SignatureAlgorithm::RsaSha256,
            $this->issuer,
        );

        // Then
        $bytes = new Serializer()->serialize($twice);
        static::assertSame(Fixtures::bytes('behaviour/signed-by-the-signer-both-rsa-sha256.xml'), $bytes);
        $loaded = Loaded::document($bytes);
        $response = $this->verifier->verify($loaded->elementById(Built::RESPONSE_ID), $this->trusted);
        static::assertStringContainsString('<ds:Signature', $response->canonical->bytes);
        $assertion = $this->verifier->verify($loaded->elementById(Built::ASSERTION_ID), $this->trusted);
        static::assertSame('Assertion', $assertion->document->root()->localName);
    }

    /**
     * §9.3 rows 6 and 7: on an entity descriptor with $after null, the Signature is the first child; with a
     * certificate, KeyInfo/X509Data/X509Certificate holds its base64 without armour or whitespace. The bytes are
     * those xmlsec1 verified, rsa-sha512 and sha512.
     */
    #[Test]
    public function itSignsAnEntityDescriptorFirstWithTheCertificate(): void
    {
        // Given
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');

        // When
        $signed = $this->signer->sign(
            Built::entityDescriptor(),
            '_entity-h7i8j9',
            $this->key,
            SignatureAlgorithm::RsaSha512,
            null,
            $certificate,
            digest: DigestAlgorithm::Sha512,
        );

        // Then
        $bytes = new Serializer()->serialize($signed);
        static::assertSame(Fixtures::bytes('behaviour/signed-by-the-signer-entity-rsa-sha512.xml'), $bytes);
        $signature = Children::all($signed->root())[0];
        static::assertSame('Signature', $signature->localName);
        $keyInfo = Children::one($signature, new Name(self::DSIG, 'KeyInfo'));
        $x509 = Children::one(
            Children::one($keyInfo, new Name(self::DSIG, 'X509Data')),
            new Name(self::DSIG, 'X509Certificate'),
        );
        static::assertMatchesRegularExpression('~^[A-Za-z0-9+/]+=*$~', Text::of($x509));
        static::assertTrue(str_starts_with(Text::of($x509), 'MII'));
    }

    /**
     * §9.3 row 8: without a certificate, no KeyInfo.
     */
    #[Test]
    public function itWritesNoKeyInfoWithoutACertificate(): void
    {
        // When
        $signed = $this->signer->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            $this->key,
            after: $this->issuer,
        );

        // Then
        $signature = Children::one($signed->elementById(Built::ASSERTION_ID), new Name(self::DSIG, 'Signature'));
        static::assertNull(Children::optional($signature, new Name(self::DSIG, 'KeyInfo')));
    }

    /**
     * §9.3 row 9: the given document is untouched, sign() returning a new one.
     */
    #[Test]
    public function itLeavesTheGivenDocumentUntouched(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $before = new Serializer()->serialize($document);

        // When
        $signed = $this->signer->sign($document, Built::ASSERTION_ID, $this->key, after: $this->issuer);

        // Then
        static::assertNotSame($document, $signed);
        static::assertSame($before, new Serializer()->serialize($document));
    }

    /**
     * §9.3 row 10: each scheme and each digest, exclusive and exclusive with comments, verified by the verifier of
     * this namespace after a round trip.
     */
    #[Test]
    #[DataProvider('provideSchemes')]
    public function itSignsWithEachSchemeAndDigest(
        SignatureAlgorithm $algorithm,
        DigestAlgorithm $digest,
        CanonicalizationMethod $method,
    ): void {
        // Given
        $document = Built::responseWithAssertion();

        // When
        $signed = $this->signer->sign(
            $document,
            Built::ASSERTION_ID,
            $this->key,
            $algorithm,
            $this->issuer,
            null,
            $method,
            $digest,
        );

        // Then
        $bytes = new Serializer()->serialize($signed);
        $loaded = Loaded::document($bytes);
        $verified = $this->verifier->verify($loaded->elementById(Built::ASSERTION_ID), $this->trusted);
        static::assertSame($algorithm, $verified->algorithm);
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, DigestAlgorithm, CanonicalizationMethod}>
     */
    public static function provideSchemes(): iterable
    {
        yield 'rsa-sha256, sha256' => [
            SignatureAlgorithm::RsaSha256,
            DigestAlgorithm::Sha256,
            CanonicalizationMethod::Exclusive,
        ];
        yield 'rsa-sha384, sha384' => [
            SignatureAlgorithm::RsaSha384,
            DigestAlgorithm::Sha384,
            CanonicalizationMethod::Exclusive,
        ];
        yield 'rsa-sha512, sha512' => [
            SignatureAlgorithm::RsaSha512,
            DigestAlgorithm::Sha512,
            CanonicalizationMethod::Exclusive,
        ];
        yield 'rsa-sha256, sha512, exclusive with comments' => [
            SignatureAlgorithm::RsaSha256,
            DigestAlgorithm::Sha512,
            CanonicalizationMethod::ExclusiveWithComments,
        ];
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            yield 'PSS with SHA-256' => [
                SignatureAlgorithm::RsaPssSha256,
                DigestAlgorithm::Sha256,
                CanonicalizationMethod::Exclusive,
            ];
            yield 'PSS with SHA-384' => [
                SignatureAlgorithm::RsaPssSha384,
                DigestAlgorithm::Sha384,
                CanonicalizationMethod::Exclusive,
            ];
            yield 'PSS with SHA-512' => [
                SignatureAlgorithm::RsaPssSha512,
                DigestAlgorithm::Sha512,
                CanonicalizationMethod::ExclusiveWithComments,
            ];
        }
    }

    /**
     * §9.1, section 13: a PSS scheme on a build without OPENSSL_PKCS1_PSS_PADDING is refused before anything is
     * serialized.
     */
    #[Test]
    public function itRefusesPssWhereTheBuildCannotProduceIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is available on this build; the refusal is the business of PHP 8.4.');
        }
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot produce RSASSA-PSS: OPENSSL_PKCS1_PSS_PADDING is undefined before PHP 8.5 (section 13).');

        // When
        $this->signer->sign(
            $document,
            Built::ASSERTION_ID,
            $this->key,
            SignatureAlgorithm::RsaPssSha256,
            $this->issuer,
        );
    }

    /**
     * §9.3 row 11: a document that would not round-trip is refused by Core's serializer before anything is signed.
     */
    #[Test]
    public function itsSerializerRefusesWhatWouldNotRoundTripBeforeSigning(): void
    {
        // Given
        $document = Built::responseWithAssertion();
        $xml = $document->root()->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);
        $document->root()->appendChild($xml->createTextNode("a carriage return\r"));

        // Then
        $this->expectException(SerializationFailed::class);

        // When
        $this->signer->sign($document, Built::ASSERTION_ID, $this->key, after: $this->issuer);
    }

    /**
     * §9.3 row 12: a SigningKeyInterface that is not PrivateKey receives the canonical SignedInfo and the scheme,
     * and what it answers is the SignatureValue.
     */
    #[Test]
    public function itSignsThroughThePort(): void
    {
        // Given
        $recording = new RecordingKey(str_repeat("\x2a", 256));

        // When
        $signed = $this->signer->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            $recording,
            SignatureAlgorithm::RsaSha384,
            $this->issuer,
        );

        // Then
        $asked = $recording->bytes ?? '';
        static::assertNotSame('', $asked);
        static::assertTrue(str_starts_with($asked, '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'));
        static::assertStringContainsString('#rsa-sha384', $asked);
        static::assertSame(SignatureAlgorithm::RsaSha384, $recording->algorithm);
        $signature = Children::one($signed->elementById(Built::ASSERTION_ID), new Name(self::DSIG, 'Signature'));
        static::assertSame(
            str_repeat('Kioq', 19),
            substr(Text::of(Children::one($signature, new Name(self::DSIG, 'SignatureValue'))), 0, 76),
        );
    }

    /**
     * D-4: an inclusive canonicalization method is a programming error.
     */
    #[Test]
    public function itRefusesAnInclusiveMethod(): void
    {
        // Given
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The canonicalization method is exclusive, with or without comments (D-4).');

        // When
        $this->signer->sign($document, Built::ASSERTION_ID, $this->key, method: CanonicalizationMethod::Inclusive);
    }

    /**
     * Section 6.2 step 3: an ID the loaded document does not hold.
     */
    #[Test]
    public function itRefusesAnUnknownId(): void
    {
        // Given
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(UnknownId::class);

        // When
        $this->signer->sign($document, '_nobody', $this->key);
    }

    /**
     * Section 6.2 step 3: $after names no child of the element.
     */
    #[Test]
    public function itRefusesAnAfterThatNamesNoChild(): void
    {
        // Given
        $document = Built::responseWithAssertion();

        // Then
        $this->expectException(MissingChild::class);

        // When
        $this->signer->sign(
            $document,
            Built::ASSERTION_ID,
            $this->key,
            after: new Name(Stack::SAML_ASSERTION, 'Advice'),
        );
    }

    /**
     * Section 6.2 step 6: the Signature sits where the consumer said, and SignedInfo names what was asked.
     */
    #[Test]
    public function itWritesTheSignedInfoTheConsumerAskedFor(): void
    {
        // When
        $signed = $this->signer->sign(
            Built::responseWithAssertion(),
            Built::ASSERTION_ID,
            $this->key,
            SignatureAlgorithm::RsaSha384,
            $this->issuer,
            null,
            CanonicalizationMethod::ExclusiveWithComments,
            DigestAlgorithm::Sha384,
        );

        // Then
        $signature = Children::one($signed->elementById(Built::ASSERTION_ID), new Name(self::DSIG, 'Signature'));
        $signedInfo = Children::one($signature, new Name(self::DSIG, 'SignedInfo'));
        $children = Children::all($signedInfo);
        static::assertSame(
            CanonicalizationMethod::ExclusiveWithComments->value,
            $children[0]->getAttribute('Algorithm'),
        );
        static::assertSame(SignatureAlgorithm::RsaSha384->value, $children[1]->getAttribute('Algorithm'));
        static::assertSame('#' . Built::ASSERTION_ID, $children[2]->getAttribute('URI'));
        $transforms = Children::all(Children::one($children[2], new Name(self::DSIG, 'Transforms')));
        static::assertSame(
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            $transforms[0]->getAttribute('Algorithm'),
        );
        static::assertSame(
            CanonicalizationMethod::ExclusiveWithComments->value,
            $transforms[1]->getAttribute('Algorithm'),
        );
        static::assertSame(
            DigestAlgorithm::Sha384->value,
            $this->child($children[2], 'DigestMethod')->getAttribute('Algorithm'),
        );
    }

    private function child(Element $parent, string $local): Element
    {
        return Children::one($parent, new Name(self::DSIG, $local));
    }
}
