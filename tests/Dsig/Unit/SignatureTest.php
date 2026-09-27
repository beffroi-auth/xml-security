<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Throwable;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\Signature;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.3, D-9: the ds:Signature element read strictly, nothing computed; KeyInfo never read (D-7); every
 * shape of section 9.2 the model refuses, with its rule named (D-13).
 */
final class SignatureTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 5.3: the signature of the vector, every field where section 9.1 says it is.
     */
    #[Test]
    public function itReadsTheSignatureOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $element = $this->signatureOf($document->elementById('_assertion-d4e5f6'));

        // When
        $signature = Signature::of($element);

        // Then
        static::assertSame($element, $signature->element);
        static::assertSame(CanonicalizationMethod::Exclusive, $signature->signedInfo->canonicalizationMethod);
        static::assertSame([], $signature->signedInfo->inclusiveNamespaces->prefixes);
        static::assertSame(SignatureAlgorithm::RsaSha256, $signature->signedInfo->signatureMethod);
        static::assertSame('_assertion-d4e5f6', $signature->signedInfo->reference->id);
        static::assertSame(CanonicalizationMethod::Exclusive, $signature->signedInfo->reference->canonicalization);
        static::assertSame([], $signature->signedInfo->reference->inclusiveNamespaces->prefixes);
        static::assertSame(DigestAlgorithm::Sha256, $signature->signedInfo->reference->digestMethod);
        static::assertSame(32, strlen($signature->signedInfo->reference->digestValue));
        static::assertSame(256, strlen($signature->signatureValue));
    }

    /**
     * Section 5.3, D-7: a Signature without KeyInfo reads the same, since KeyInfo is never read.
     */
    #[Test]
    public function itReadsASignatureWithoutKeyInfo(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/keyinfo-absent-loads.xml');

        // When
        $signature = Signature::of($this->signatureOf($document->elementById('_assertion-d4e5f6')));

        // Then
        static::assertSame(256, strlen($signature->signatureValue));
    }

    /**
     * §9.2 row 13, D-8: a DigestValue split by a comment reads as one value, Text::of() concatenating.
     */
    #[Test]
    public function itReadsADigestValueSplitByAComment(): void
    {
        // Given
        $vectorDocument = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $vector = Signature::of($this->signatureOf($vectorDocument->elementById('_assertion-d4e5f6')));
        $document = Loaded::fixture('behaviour/digest-value-comment-split-loads.xml');

        // When
        $signature = Signature::of($this->signatureOf($document->elementById('_assertion-d4e5f6')));

        // Then
        static::assertSame($vector->signedInfo->reference->digestValue, $signature->signedInfo->reference->digestValue);
    }

    /**
     * §9.2 rows 3, 7 to 12 and 18 to 33, D-2, D-3, D-4, D-5, D-8, D-9, D-14: every shape the model refuses, with the
     * rule named and never the input (D-13).
     *
     * @param class-string<\Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedShapes')]
    public function itRefusesAShapeOfTheHostileCorpus(string $fixture, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = $this->signatureOf($document->elementById('_assertion-d4e5f6'));

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        Signature::of($element);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function provideRefusedShapes(): iterable
    {
        $otherChild = 'A Signature holds a child other than SignedInfo, SignatureValue and KeyInfo (D-9).';
        $uri = 'A Reference names the claimed element by its ID, "#" followed by an NCName (D-2).';
        $algorithm = 'The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).';
        $digest = 'The digest algorithm is not SHA-256, SHA-384 or SHA-512 (D-5).';
        $exclusive = 'The canonicalization method is not exclusive (D-4).';
        $transforms = 'The transforms are the enveloped signature transform then an exclusive canonicalization, and nothing else (D-3).';
        $base64 = 'A base64 value holds a character outside the alphabet or is empty (D-8).';
        $signatureValue = 'A SignatureValue is not between 256 and maxSignatureValueBytes, 1024 bytes (D-14).';

        yield 'row 3, the assertion inside a ds:Object' => [
            'object-inside-signature-refused.xml',
            MalformedSignature::class,
            $otherChild,
        ];
        yield 'row 7, an empty URI' => ['reference-uri-empty-refused.xml', MalformedSignature::class, $uri];
        yield 'row 8, an xpointer URI' => ['reference-uri-xpointer-refused.xml', MalformedSignature::class, $uri];
        yield 'row 9, an external URI' => ['reference-uri-external-refused.xml', MalformedSignature::class, $uri];
        yield 'row 10, a Type naming a Manifest inside an Object' => [
            'reference-type-manifest-refused.xml',
            MalformedSignature::class,
            $otherChild,
        ];
        yield 'row 10, a Type alone' => [
            'reference-type-refused.xml',
            MalformedSignature::class,
            'A Reference carries no Type (D-2).',
        ];
        yield 'row 11, two references' => [
            'two-references-refused.xml',
            MalformedSignature::class,
            'A SignedInfo holds exactly one Reference (D-2).',
        ];
        yield 'row 12, two SignedInfo' => [
            'two-signedinfo-refused.xml',
            MalformedSignature::class,
            'A Signature holds exactly one SignedInfo (D-9).',
        ];
        yield 'row 18, rsa-sha1' => [
            'signature-method-rsa-sha1-refused.xml',
            UnknownSignatureAlgorithm::class,
            $algorithm,
        ];
        yield 'row 19, hmac-sha256 with an output length' => [
            'signature-method-hmac-sha256-refused.xml',
            UnknownSignatureAlgorithm::class,
            $algorithm,
        ];
        yield 'row 20, dsa-sha256' => [
            'signature-method-dsa-sha256-refused.xml',
            UnknownSignatureAlgorithm::class,
            $algorithm,
        ];
        yield 'row 20, ecdsa-sha256' => [
            'signature-method-ecdsa-sha256-refused.xml',
            UnknownSignatureAlgorithm::class,
            $algorithm,
        ];
        yield 'a SignatureMethod with a child' => [
            'signature-method-with-a-child-refused.xml',
            MalformedSignature::class,
            'A SignatureMethod holds no child (D-9).',
        ];
        yield 'a SignatureMethod without Algorithm' => [
            'signature-method-without-algorithm-refused.xml',
            MalformedSignature::class,
            'A SignatureMethod names its Algorithm (D-5).',
        ];
        yield 'row 21, sha1' => ['digest-method-sha1-refused.xml', UnknownDigestAlgorithm::class, $digest];
        yield 'row 21, md5' => ['digest-method-md5-refused.xml', UnknownDigestAlgorithm::class, $digest];
        yield 'a DigestMethod without Algorithm' => [
            'digest-method-without-algorithm-refused.xml',
            MalformedSignature::class,
            'A DigestMethod names its Algorithm (D-5).',
        ];
        yield 'a DigestMethod with a child' => [
            'digest-method-with-a-child-refused.xml',
            MalformedSignature::class,
            'A DigestMethod holds no child (D-9).',
        ];
        yield 'row 22, inclusive canonicalization' => [
            'canonicalization-inclusive-refused.xml',
            MalformedSignature::class,
            $exclusive,
        ];
        yield 'row 22, inclusive canonicalization with comments' => [
            'canonicalization-inclusive-with-comments-refused.xml',
            MalformedSignature::class,
            $exclusive,
        ];
        yield 'an unknown canonicalization, Canonical XML 1.1' => [
            'canonicalization-unknown-refused.xml',
            MalformedSignature::class,
            $exclusive,
        ];
        yield 'a CanonicalizationMethod with another child' => [
            'canonicalization-with-a-child-refused.xml',
            MalformedSignature::class,
            'A CanonicalizationMethod holds nothing but an InclusiveNamespaces (D-9).',
        ];
        yield 'row 23, an inclusive canonicalization transform' => [
            'transform-inclusive-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 24, the enveloped transform alone' => [
            'transform-enveloped-alone-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 25, the two transforms in the other order' => [
            'transforms-other-order-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 26, a third transform, XPath' => [
            'transform-third-xpath-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 26, a third transform, XSLT' => [
            'transform-third-xslt-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 26, a third transform, base64' => [
            'transform-third-base64-refused.xml',
            MalformedSignature::class,
            $transforms,
        ];
        yield 'row 27, no Transforms' => [
            'transforms-missing-refused.xml',
            MalformedSignature::class,
            'A Reference holds exactly one Transforms (D-3).',
        ];
        yield 'an enveloped transform with a child' => [
            'transform-enveloped-with-a-child-refused.xml',
            MalformedSignature::class,
            'The enveloped signature transform holds no child (D-9).',
        ];
        yield 'a canonicalization transform with another child' => [
            'transform-canonicalization-with-a-child-refused.xml',
            MalformedSignature::class,
            'A canonicalization transform holds nothing but an InclusiveNamespaces (D-9).',
        ];
        yield 'row 28, a PrefixList of 33 prefixes' => [
            'prefixlist-33-refused.xml',
            LimitExceeded::class,
            'A PrefixList holds more prefixes than maxPrefixes, 32 (D-14).',
        ];
        yield 'an InclusiveNamespaces without PrefixList' => [
            'inclusive-namespaces-without-prefixlist-refused.xml',
            MalformedSignature::class,
            'An InclusiveNamespaces names its PrefixList (D-9).',
        ];
        yield 'row 29, a SignatureValue of 255 bytes' => [
            'signature-value-255-bytes-refused.xml',
            LimitExceeded::class,
            $signatureValue,
        ];
        yield 'row 29, a SignatureValue of 1025 bytes' => [
            'signature-value-1025-bytes-refused.xml',
            LimitExceeded::class,
            $signatureValue,
        ];
        yield 'row 30, a character outside the base64 alphabet' => [
            'signature-value-alphabet-refused.xml',
            MalformedSignature::class,
            $base64,
        ];
        yield 'row 31, a DigestValue of 31 bytes' => [
            'digest-value-31-bytes-refused.xml',
            MalformedSignature::class,
            'A DigestValue is not the length of its digest (D-14).',
        ];
        yield 'row 32, an empty SignatureValue' => [
            'signature-value-empty-refused.xml',
            MalformedSignature::class,
            $base64,
        ];
        yield 'row 32, an empty DigestValue' => ['digest-value-empty-refused.xml', MalformedSignature::class, $base64];
        yield 'row 33, a SignatureValue text of more than 4096 bytes' => [
            'signature-value-4097-bytes-refused.xml',
            LimitExceeded::class,
            'A base64 value is longer than maxBase64Bytes, 4096 bytes (D-14).',
        ];
        yield 'two KeyInfo' => [
            'two-keyinfo-refused.xml',
            MalformedSignature::class,
            'A Signature holds at most one KeyInfo (D-9).',
        ];
        yield 'no SignatureValue' => [
            'signature-value-missing-refused.xml',
            MalformedSignature::class,
            'A Signature holds exactly one SignatureValue (D-9).',
        ];
        yield 'a SignedInfo with another child' => [
            'signedinfo-with-another-child-refused.xml',
            MalformedSignature::class,
            'A SignedInfo holds a child other than CanonicalizationMethod, SignatureMethod and Reference (D-9).',
        ];
        yield 'a Reference with another child' => [
            'reference-with-another-child-refused.xml',
            MalformedSignature::class,
            'A Reference holds a child other than Transforms, DigestMethod and DigestValue (D-9).',
        ];
        yield 'a Reference without DigestMethod' => [
            'reference-missing-digest-method-refused.xml',
            MalformedSignature::class,
            'A Reference holds exactly one DigestMethod (D-9).',
        ];
    }

    /**
     * Section 5.3, D-9: an element that is not a ds:Signature.
     */
    #[Test]
    public function itRefusesAnElementThatIsNotASignature(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $assertion = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('The element is not a ds:Signature (D-9).');

        // When
        Signature::of($assertion);
    }

    /**
     * §9.2 row 40, Core I-4: an element of a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        Signature::of($root);
    }

    private function signatureOf(Element $signed): Element
    {
        return Children::one($signed, new Name(self::DSIG, 'Signature'));
    }
}
