<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Throwable;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureRefused;
use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use function count;
use function is_subclass_of;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.7, the adversarial pass of 27 September 2026: each row of section 3 attacked with inputs the corpus of
 * 9.2 does not list, every attempt a fixture whatever its outcome, refused with the exception and the message it
 * got, or verified when the attempt changes nothing the signature covers. None bypassed a rule.
 */
final class AdversarialTest extends TestCase
{
    private Verifier $verifier;

    private VerificationKeys $trusted;

    protected function setUp(): void
    {
        $this->verifier = new Verifier(new Loader(Stack::idAttributes()));
        $this->trusted = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);
    }

    /**
     * Section 9.7, D-1, D-2, D-3, D-5, D-6, D-8, D-9: every attempt the verifier refuses, with its rule named.
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedAttempts')]
    public function itRefusesAnAttemptWithTheRuleNamed(
        string $fixture,
        string $id,
        string $exception,
        string $message,
    ): void {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $claimed = $document->elementById($id);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->verifier->verify($claimed, $this->trusted);
    }

    /**
     * @return iterable<string, array{string, string, class-string<Throwable>, string}>
     */
    public static function provideRefusedAttempts(): iterable
    {
        $id = '_assertion-d4e5f6';
        $unknown = 'The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).';
        $mismatch = 'No trusted key verifies the signature over SignedInfo (D-7, D-8).';
        $base64 = 'A base64 value holds a character outside the alphabet or is empty (D-8).';
        $uri = 'A Reference names the claimed element by its ID, "#" followed by an NCName (D-2).';
        $transforms = 'The transforms are the enveloped signature transform then an exclusive canonicalization, and nothing else (D-3).';
        $wrong = 'The reference does not name the claimed element (D-2).';

        yield 'an algorithm URI in upper case' => [
            'adversarial-algorithm-uppercase-refused.xml',
            $id,
            UnknownSignatureAlgorithm::class,
            $unknown,
        ];
        yield 'an algorithm URI with a trailing slash' => [
            'adversarial-algorithm-trailing-slash-refused.xml',
            $id,
            UnknownSignatureAlgorithm::class,
            $unknown,
        ];
        yield 'an algorithm URI surrounded by spaces' => [
            'adversarial-algorithm-surrounded-by-spaces-refused.xml',
            $id,
            UnknownSignatureAlgorithm::class,
            $unknown,
        ];
        yield 'an empty Algorithm attribute' => [
            'adversarial-empty-algorithm-attribute-refused.xml',
            $id,
            UnknownSignatureAlgorithm::class,
            $unknown,
        ];
        yield 'a digest URI in upper case' => [
            'adversarial-digest-algorithm-uppercase-refused.xml',
            $id,
            UnknownDigestAlgorithm::class,
            'The digest algorithm is not SHA-256, SHA-384 or SHA-512 (D-5).',
        ];
        yield 'extra padding on the SignatureValue' => [
            'adversarial-signature-value-extra-padding-refused.xml',
            $id,
            MalformedSignature::class,
            $base64,
        ];
        yield 'the URL-safe base64 alphabet' => [
            'adversarial-signature-value-url-safe-alphabet-refused.xml',
            $id,
            MalformedSignature::class,
            $base64,
        ];
        yield 'a processing instruction inside SignedInfo, which the canonical form renders' => [
            'adversarial-pi-inside-signedinfo-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'SignedInfo under another prefix of the same namespace, which the canonical form renders' => [
            'adversarial-signedinfo-other-prefix-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'a PrefixList added to the CanonicalizationMethod, which changes SignedInfo' => [
            'adversarial-prefixlist-added-to-method-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'a PrefixList added to the transform, which changes SignedInfo' => [
            'adversarial-prefixlist-added-to-transform-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'a reference by xpointer(id())' => [
            'adversarial-reference-xpointer-id-refused.xml',
            $id,
            MalformedSignature::class,
            $uri,
        ];
        yield 'a reference to the KeyInfo, which changes SignedInfo before the reference is read' => [
            'adversarial-reference-to-keyinfo-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'an ID that differs by case only, claimed after the wrapping' => [
            'adversarial-id-case-variant-refused.xml',
            '_ASSERTION-D4E5F6',
            WrongReference::class,
            $wrong,
        ];
        yield 'an ID that differs by a combining character only, claimed after the wrapping' => [
            'adversarial-id-unicode-variant-refused.xml',
            "_assertion-d4e5f6\u{301}",
            WrongReference::class,
            $wrong,
        ];
        yield 'a Signature in a namespace that is almost the right one' => [
            'adversarial-signature-in-other-namespace-refused.xml',
            $id,
            MissingChild::class,
            'The element has no child named {http://www.w3.org/2000/09/xmldsig#}Signature (section 6.4).',
        ];
        yield 'the enveloped transform URI in another case' => [
            'adversarial-enveloped-uri-uppercase-refused.xml',
            $id,
            MalformedSignature::class,
            $transforms,
        ];
        yield 'a transform without Algorithm' => [
            'adversarial-transform-without-algorithm-refused.xml',
            $id,
            MalformedSignature::class,
            $transforms,
        ];
        yield 'a DigestMethod in another namespace' => [
            'adversarial-digest-method-other-namespace-refused.xml',
            $id,
            MalformedSignature::class,
            'A Reference holds a child other than Transforms, DigestMethod and DigestValue (D-9).',
        ];
        yield 'an element inside SignatureValue' => [
            'adversarial-signature-value-with-element-refused.xml',
            $id,
            MalformedSignature::class,
            'A SignatureValue holds nothing but text (D-9).',
        ];
        yield 'a second Signature in another namespace, inside the signed content' => [
            'adversarial-second-signature-other-namespace-refused.xml',
            $id,
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'xml:space on SignedInfo, an attribute the canonical form renders' => [
            'adversarial-xml-space-on-signedinfo-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
        yield 'SignedInfo re-indented, whitespace the canonical form keeps' => [
            'adversarial-signedinfo-reindented-refused.xml',
            $id,
            SignatureMismatch::class,
            $mismatch,
        ];
    }

    /**
     * Section 9.7, Core I-1 and I-8: two attempts the loader refuses before anything is verified.
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideAttemptsRefusedAtLoad')]
    public function itsLoaderRefusesAnAttemptWithTheRuleNamed(string $fixture, string $exception, string $message): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/' . $fixture);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        Loaded::document($bytes);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function provideAttemptsRefusedAtLoad(): iterable
    {
        yield 'a document type declaration' => [
            'adversarial-doctype-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'the Id of the Signature equal to the ID of the assertion' => [
            'adversarial-signature-id-equals-assertion-id-refused.xml',
            DuplicateId::class,
            'An ID value appears twice in the document (I-8).',
        ];
    }

    /**
     * Section 9.7, D-7, D-8, D-10: attempts that change nothing the signature covers verify, and what comes back is
     * still the signed element.
     */
    #[Test]
    #[DataProvider('provideHarmlessAttempts')]
    public function itVerifiesAnAttemptThatChangesNothingTheSignatureCovers(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('behaviour/' . $fixture);

        // When
        $verified = $this->verifier->verify($document->elementById('_assertion-d4e5f6'), $this->trusted);

        // Then
        static::assertSame('Assertion', $verified->document->root()->localName);
        static::assertStringNotContainsString('attacker', $verified->canonical->bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHarmlessAttempts(): iterable
    {
        yield 'tabs and spaces inside the SignatureValue' => ['adversarial-signature-value-with-tabs-verifies.xml'];
        yield 'a comment inside SignedInfo, which the canonical form drops' => [
            'adversarial-comment-inside-signedinfo-verifies.xml',
        ];
        yield 'SignedInfo redeclaring the same namespace' => ['adversarial-signedinfo-redeclares-ds-verifies.xml'];
        yield 'the DigestValue inside a CDATA section' => ['adversarial-cdata-digest-value-verifies.xml'];
        yield 'an ID attribute on the Signature, which no ID attribute of the stack registers' => [
            'adversarial-id-attribute-on-signature-verifies.xml',
        ];
        yield 'garbage inside KeyInfo, which is never read' => ['adversarial-keyinfo-with-garbage-verifies.xml'];
    }

    /**
     * §9.3 row 17, D-13: every refusal of the pass ends with the rule in parentheses and carries no URI, no ID and
     * no base64.
     */
    #[Test]
    public function itsRefusalsNameTheRuleAndNothingOfTheInput(): void
    {
        // Given
        $messages = [];
        foreach (self::provideRefusedAttempts() as [, , $exception, $message]) {
            if (! is_subclass_of($exception, SignatureRefused::class)) {
                continue;
            }

            $messages[] = $message;
        }
        static::assertGreaterThan(15, count($messages));

        // When / Then
        foreach ($messages as $message) {
            static::assertMatchesRegularExpression('~\((D-\d+(, D-\d+)*|I-\d+|section [0-9.]+)\)\.$~', $message);
            static::assertStringNotContainsString('http', $message);
            static::assertStringNotContainsString('_assertion', $message);
            static::assertDoesNotMatchRegularExpression('~[A-Za-z0-9+/]{20}~', $message);
        }
    }
}
