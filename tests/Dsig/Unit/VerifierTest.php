<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Throwable;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use function defined;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_starts_with;

/**
 * Section 6.1, D-1 to D-10: verification in the order that bounds the cost, against the vectors an independent
 * implementation produced (section 9.1) and the wrapping and mismatch variants of section 9.2.
 */
final class VerifierTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private Verifier $verifier;

    private VerificationKeys $trusted;

    protected function setUp(): void
    {
        $this->verifier = new Verifier(new Loader(Stack::idAttributes()));
        $this->trusted = new VerificationKeys([$this->key('test-signing-certificate.pem')]);
    }

    /**
     * §9.1, §9.3 row 1, D-10: every vector verifies, and what comes back is the reload of the hashed bytes: one
     * root, the claimed element without its Signature, the algorithm the signer used, the key that verified.
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itVerifiesAVector(string $fixture, string $id, string $root, SignatureAlgorithm $algorithm): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $signed = $document->elementById($id);

        // When
        $verified = $this->verifier->verify($signed, $this->trusted);

        // Then
        static::assertSame($root, $verified->document->root()->localName);
        static::assertSame($id, $verified->document->root()->getAttribute('ID'));
        static::assertSame([], Children::named($verified->document->root(), new Name(self::DSIG, 'Signature')));
        static::assertSame($algorithm, $verified->algorithm);
        static::assertSame($this->trusted->keys[0], $verified->key);
        static::assertTrue(str_starts_with($verified->canonical->bytes, '<' . $verified->document->root()->tagName));
    }

    /**
     * @return iterable<string, array{string, string, string, SignatureAlgorithm}>
     */
    public static function provideVectors(): iterable
    {
        yield 'rsa-sha256' => [
            'response-assertion-rsa-sha256.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'rsa-sha384' => [
            'response-assertion-rsa-sha384.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha384,
        ];
        yield 'rsa-sha512' => [
            'response-assertion-rsa-sha512.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha512,
        ];
        yield 'exclusive with comments, a comment inside the signed text' => [
            'response-assertion-with-comments.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'a PrefixList on the transform' => [
            'response-assertion-prefixlist.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'an entity descriptor, the Signature first' => [
            'entity-descriptor-rsa-sha256.xml',
            '_entity-m1n2o3',
            'EntityDescriptor',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'the assertion of a doubly signed response' => [
            'response-and-assertion-both-signed.xml',
            '_assertion-d4e5f6',
            'Assertion',
            SignatureAlgorithm::RsaSha256,
        ];
        yield 'the response of a doubly signed response' => [
            'response-and-assertion-both-signed.xml',
            '_response-a1b2c3',
            'Response',
            SignatureAlgorithm::RsaSha256,
        ];
        if (defined('OPENSSL_PKCS1_PSS_PADDING')) {
            yield 'RSASSA-PSS with SHA-256' => [
                'response-assertion-rsa-pss-sha256.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha256,
            ];
            yield 'RSASSA-PSS with SHA-384' => [
                'response-assertion-rsa-pss-sha384.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha384,
            ];
            yield 'RSASSA-PSS with SHA-512' => [
                'response-assertion-rsa-pss-sha512.xml',
                '_assertion-d4e5f6',
                'Assertion',
                SignatureAlgorithm::RsaPssSha512,
            ];
        }
    }

    /**
     * §9.1, section 6.1 step 8: the comment inside the signed text is not in the hashed bytes, whatever the
     * transform says, since the node-set of a same-document reference omits comments (XML Signature 1.1 §4.4.3.3).
     */
    #[Test]
    public function itsCanonicalBytesOmitTheCommentsWhateverTheTransformSays(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-with-comments.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertStringNotContainsString('<!--', $verified->canonical->bytes);
        static::assertStringContainsString('>user-0001<', $verified->canonical->bytes);
    }

    /**
     * §9.1, D-10: the response of a doubly signed response is verified over bytes that hold the assertion's
     * Signature, as SAML wants.
     */
    #[Test]
    public function itsCanonicalBytesOfAResponseHoldTheAssertionsSignature(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-and-assertion-both-signed.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_response-a1b2c3'), $this->trusted);

        // Then
        static::assertStringContainsString('<ds:Signature', $verified->canonical->bytes);
        static::assertCount(
            1,
            Children::named(
                Children::one($verified->document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion')),
                new Name(self::DSIG, 'Signature'),
            ),
        );
    }

    /**
     * §9.1, section 13: a PSS vector on a build without OPENSSL_PKCS1_PSS_PADDING is refused by name, before any
     * key is touched.
     */
    #[Test]
    public function itRefusesPssWhereTheBuildCannotVerifyIt(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is available on this build; the refusal is the business of PHP 8.4.');
        }
        $document = Loaded::fixture('vectors/response-assertion-rsa-pss-sha256.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot verify RSASSA-PSS: OPENSSL_PKCS1_PSS_PADDING is undefined before PHP 8.5 (section 13).');

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * §9.3 row 2, D-7: the verifier tries each trusted key and stops at the first that verifies.
     */
    #[Test]
    public function itVerifiesWithTheSecondKeyWhenTheFirstIsAStranger(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $stranger = $this->key('stranger-certificate.pem');
        $right = $this->key('test-signing-certificate.pem');

        // When
        $verified = $this->verifier->verify(
            $document->elementById('_assertion-d4e5f6'),
            new VerificationKeys([$stranger, $right]),
        );

        // Then
        static::assertSame($right, $verified->key);
    }

    /**
     * §9.3 row 2, D-7: with the right key absent, nothing verifies, and the message names no key.
     */
    #[Test]
    public function itRefusesWhenNoTrustedKeyVerifies(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the signature over SignedInfo (D-7, D-8).');

        // When
        $this->verifier->verify($signed, new VerificationKeys([$this->key('stranger-certificate.pem')]));
    }

    /**
     * §9.3 row 3, D-1, D-10: an unsigned assertion elsewhere in the document changes nothing, and the element the
     * consumer passed keeps its Signature and is untouched.
     */
    #[Test]
    public function itReadsNothingOfTheDocumentButTheClaimedElementAndItsSignature(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/unsigned-assertion-elsewhere-verifies.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // When
        $verified = $this->verifier->verify($signed, $this->trusted);

        // Then
        static::assertSame('_assertion-d4e5f6', $verified->document->root()->getAttribute('ID'));
        static::assertStringNotContainsString('attacker', $verified->canonical->bytes);
        static::assertCount(1, Children::named($signed, new Name(self::DSIG, 'Signature')));
        static::assertTrue($document->hasId('_other-x1y2z3'));
    }

    /**
     * §9.2 row 13, D-8: a DigestValue split by a comment verifies, SignedInfo being canonicalized without comments.
     */
    #[Test]
    public function itVerifiesADigestValueSplitByAComment(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/digest-value-comment-split-loads.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertSame('Assertion', $verified->document->root()->localName);
    }

    /**
     * §9.2 row 1, Core I-8: the signed assertion moved into Extensions and an unsigned one with the same ID in its
     * place, the first wrapping of 2012, refused at load before anything is verified.
     */
    #[Test]
    public function itsLoaderRefusesTheWrappingThatDuplicatesTheId(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/xsw-assertion-in-extensions-same-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        Loaded::document($bytes);
    }

    /**
     * §9.2 rows 2, 4, 5, 6, 14, 15, 16, 17, 37 and 38, D-1, D-2, D-7, D-8: the wrapping and mismatch variants, each
     * refused by its named rule.
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedVariants')]
    public function itRefusesAWrappingOrAMismatch(string $fixture, string $id, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $signed = $document->elementById($id);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * @return iterable<string, array{string, string, class-string<Throwable>, string}>
     */
    public static function provideRefusedVariants(): iterable
    {
        $mismatch = 'No trusted key verifies the signature over SignedInfo (D-7, D-8).';
        $missing = 'The element has no child named {http://www.w3.org/2000/09/xmldsig#}Signature (section 6.4).';

        yield 'row 2, the signed assertion wrapped, the unsigned one claimed with the copied Signature' => [
            'xsw-assertion-in-extensions-new-id-refused.xml',
            '_evil-e1f2g3',
            WrongReference::class,
            'The reference does not name the claimed element (D-2).',
        ];
        yield 'row 4, the Signature moved to the response' => [
            'xsw-signature-moved-to-response-refused.xml',
            '_assertion-d4e5f6',
            MissingChild::class,
            $missing,
        ];
        yield 'row 5, the Signature a grandchild' => [
            'xsw-signature-grandchild-refused.xml',
            '_assertion-d4e5f6',
            MissingChild::class,
            $missing,
        ];
        yield 'row 6, two Signature children' => [
            'xsw-two-signatures-refused.xml',
            '_assertion-d4e5f6',
            AmbiguousChild::class,
            'The element has more than one child named {http://www.w3.org/2000/09/xmldsig#}Signature (section 6.4).',
        ];
        yield 'row 14, a DigestValue altered' => [
            'digest-value-altered-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 15, a SignatureValue altered' => [
            'signature-value-altered-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 16, the signed element altered' => [
            'signed-element-altered-refused.xml',
            '_assertion-d4e5f6',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'row 17, re-signed with a stranger key, its certificate in KeyInfo' => [
            'resigned-with-a-stranger-key-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 37, a PSS signature claimed as PKCS#1 v1.5' => [
            'pss-signature-claimed-as-pkcs1-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'row 38, a SHA-256 signature claimed as SHA-512' => [
            'sha256-signature-claimed-as-sha512-refused.xml',
            '_assertion-d4e5f6',
            SignatureMismatch::class,
            $mismatch,
        ];
    }

    /**
     * §9.2 row 37, D-8: a PKCS#1 v1.5 signature claimed as PSS is a mismatch where PSS can be verified, and an
     * unavailable algorithm where it cannot.
     */
    #[Test]
    public function itRefusesAPkcs1SignatureClaimedAsPss(): void
    {
        // Given
        $document = Loaded::fixture('hostile/pkcs1-signature-claimed-as-pss-refused.xml');
        $signed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(
            defined('OPENSSL_PKCS1_PSS_PADDING') ? SignatureMismatch::class : AlgorithmUnavailable::class,
        );

        // When
        $this->verifier->verify($signed, $this->trusted);
    }

    /**
     * §9.2 row 40, Core I-4: the claimed element from a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse(Fixtures::bytes('vectors/response-assertion-rsa-sha256.xml'))->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        $this->verifier->verify($root, $this->trusted);
    }

    /**
     * Section 6.1 step 6: the salt of a PSS signature is not constrained, openssl_verify() recovering its length; a
     * salt of no byte verifies, which RFC 6931 does not name and which weakens nothing.
     */
    #[Test]
    public function itVerifiesAPssSignatureWhateverTheLengthOfItsSalt(): void
    {
        // Given
        if (! SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('RSASSA-PSS is not available on this build.');
        }
        $document = Loaded::fixture('behaviour/pss-salt-zero-verifies.xml');

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertSame(SignatureAlgorithm::RsaPssSha256, $verified->algorithm);
    }

    private function key(string $file): VerificationKey
    {
        return VerificationKey::fromCertificatePem(Fixtures::bytes('keys/' . $file));
    }
}
