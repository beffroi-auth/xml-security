<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use function count;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Section 9.7, the adversarial pass of 27 September 2026: each row of section 3 attacked with inputs the corpus of
 * 9.2 does not list, every attempt a fixture whatever its outcome (tests/Enc/Fixture/hostile/derive-adversarial.php),
 * refused with the exception and the message it got, failed in the one way, or decrypted when the attempt changes
 * nothing the cipher covers. None bypassed a rule, and no failing attempt said more than the one message.
 */
final class AdversarialTest extends TestCase
{
    private Decryptor $decryptor;

    private PrivateDecryptionKey $key;

    protected function setUp(): void
    {
        $this->decryptor = new Decryptor(new Loader(Stack::idAttributes()));
        $this->key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }

    /**
     * Section 9.7, E-1, E-5, E-7: every attempt the reading model refuses, with its rule named and nothing of the
     * input (E-12).
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedAttempts')]
    public function itRefusesAnAttemptWithTheRuleNamed(string $fixture, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->decryptor->decrypt($element, $this->key);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function provideRefusedAttempts(): iterable
    {
        $content = 'The content algorithm is not AES-128-GCM or AES-256-GCM (E-1).';
        $notOaep = 'The key transport is not RSA-OAEP: PKCS#1 v1.5, key wrapping and key agreement are refused by name (E-1).';
        $type = 'The Type of an EncryptedData is Element: the plaintext is a whole element or nothing (E-5).';
        $base64 = 'A CipherValue holds a character outside the base64 alphabet or is empty (E-7).';
        $oaepChild = 'An EncryptionMethod of rsa-oaep holds nothing but a DigestMethod and an MGF (E-5).';

        yield 'the content algorithm in upper case' => [
            'adversarial-content-algorithm-upper-case-refused.xml',
            UnknownContentAlgorithm::class,
            $content,
        ];
        yield 'the content algorithm with a trailing slash' => [
            'adversarial-content-algorithm-trailing-slash-refused.xml',
            UnknownContentAlgorithm::class,
            $content,
        ];
        yield 'the content algorithm with a slash for its fragment' => [
            'adversarial-content-algorithm-slash-for-fragment-refused.xml',
            UnknownContentAlgorithm::class,
            $content,
        ];
        yield 'the content algorithm surrounded by spaces' => [
            'adversarial-content-algorithm-surrounded-by-spaces-refused.xml',
            UnknownContentAlgorithm::class,
            $content,
        ];
        yield 'the key transport in upper case' => [
            'adversarial-key-transport-upper-case-refused.xml',
            UnknownKeyTransport::class,
            $notOaep,
        ];
        yield 'the key transport of 1.0 under the 1.1 namespace' => [
            'adversarial-key-transport-in-the-1-1-namespace-refused.xml',
            UnknownKeyTransport::class,
            $notOaep,
        ];
        yield 'the Type in another case' => [
            'adversarial-type-in-another-case-refused.xml',
            MalformedEncryption::class,
            $type,
        ];
        yield 'the Type with a trailing space' => [
            'adversarial-type-with-a-trailing-space-refused.xml',
            MalformedEncryption::class,
            $type,
        ];
        yield 'padding inside the cipher value' => [
            'adversarial-cipher-value-padding-inside-refused.xml',
            MalformedEncryption::class,
            $base64,
        ];
        yield 'the URL-safe base64 alphabet' => [
            'adversarial-cipher-value-url-safe-alphabet-refused.xml',
            MalformedEncryption::class,
            $base64,
        ];
        yield 'extra padding on the cipher value' => [
            'adversarial-cipher-value-extra-padding-refused.xml',
            MalformedEncryption::class,
            $base64,
        ];
        yield 'the EncryptedKey next to the EncryptedData, the sibling form of section 12' => [
            'adversarial-encrypted-key-as-a-sibling-refused.xml',
            MalformedEncryption::class,
            'The KeyInfo of an EncryptedData holds nothing but an EncryptedKey (E-5).',
        ];
        yield 'an MGF in the xmlenc namespace' => [
            'adversarial-mgf-in-the-xmlenc-namespace-refused.xml',
            MalformedEncryption::class,
            $oaepChild,
        ];
        yield 'a DigestMethod in the xmlenc namespace' => [
            'adversarial-digest-method-in-the-xmlenc-namespace-refused.xml',
            MalformedEncryption::class,
            $oaepChild,
        ];
        yield 'an element inside the CipherValue' => [
            'adversarial-element-inside-cipher-value-refused.xml',
            MixedContent::class,
            'The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).',
        ];
    }

    /**
     * Section 9.7, E-2, E-3: every attempt that passes the model fails in the one way, with the one message: the
     * cipher value shortened and lengthened around the IV and the tag, a wrapped key of the modulus length filled
     * with zeros, with ones, and equal to the modulus.
     */
    #[Test]
    #[DataProvider('provideFailingAttempts')]
    public function itFailsAnAttemptInTheOneWay(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // When
        try {
            $this->decryptor->decrypt($element, $this->key);
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame('The data could not be decrypted (E-3).', $failure->getMessage());
            static::assertNull($failure->getPrevious());

            return;
        }

        static::fail('The decryptor accepted ' . $fixture);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFailingAttempts(): iterable
    {
        yield 'the cipher value shortened by two bytes' => ['adversarial-cipher-value-shortened-by-two-refused.xml'];
        yield 'the cipher value lengthened by one byte' => ['adversarial-cipher-value-lengthened-by-one-refused.xml'];
        yield 'the cipher value lengthened by a tag of zeros' => [
            'adversarial-cipher-value-lengthened-by-sixteen-refused.xml',
        ];
        yield 'a wrapped key of zeros' => ['adversarial-wrapped-key-of-zeros-refused.xml'];
        yield 'a wrapped key of ones' => ['adversarial-wrapped-key-of-ones-refused.xml'];
        yield 'a wrapped key equal to the modulus' => ['adversarial-wrapped-key-equal-to-the-modulus-refused.xml'];
    }

    /**
     * Section 9.7, Core I-8: an Id on the EncryptedData equal to the ID of the response is refused at load, before
     * anything is read.
     */
    #[Test]
    public function itsLoaderRefusesAnIdTakenTwice(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/adversarial-encrypted-data-id-equal-to-the-response-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);

        // When
        Loaded::document($bytes);
    }

    /**
     * Section 9.7, E-5, Core I-10: an EncryptedData in a namespace that is almost the right one is not an
     * EncryptedData.
     */
    #[Test]
    public function itRefusesAnEncryptedDataInAlmostTheNamespace(): void
    {
        // Given
        $document = Loaded::fixture('hostile/adversarial-encrypted-data-in-almost-the-namespace-refused.xml');
        $element = Children::one(
            $document->root(),
            new Name(Stack::SAML_ASSERTION, 'EncryptedAssertion'),
        )->firstElementChild;
        static::assertInstanceOf(Element::class, $element);

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The element is not a xenc:EncryptedData (E-5).');

        // When
        $this->decryptor->decrypt($element, $this->key);
    }

    /**
     * Section 9.7: every attempt that changes nothing the cipher covers decrypts to the assertion of the vector.
     */
    #[Test]
    #[DataProvider('provideDecryptingAttempts')]
    public function itDecryptsAnAttemptThatChangesNothingTheCipherCovers(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('behaviour/' . $fixture);

        // When
        $decrypted = $this->decryptor->decrypt(Encrypted::dataOf($document), $this->key);

        // Then
        $root = $decrypted->root();
        static::assertSame($root, $decrypted->elementById('_assertion-d4e5f6'));
        static::assertSame(
            'https://idp.example.org',
            Text::of(Children::one($root, new Name(Stack::SAML_ASSERTION, 'Issuer'))),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDecryptingAttempts(): iterable
    {
        yield 'whitespace inside the cipher value' => ['adversarial-cipher-value-with-whitespace-inside-decrypts.xml'];
        yield 'the cipher value inside a CDATA section' => ['adversarial-cipher-value-in-cdata-decrypts.xml'];
        yield 'a comment splitting the cipher value' => ['adversarial-comment-inside-cipher-value-decrypts.xml'];
        yield 'a processing instruction before the cipher value' => [
            'adversarial-processing-instruction-inside-cipher-value-decrypts.xml',
        ];
        yield 'garbage inside the key\'s KeyInfo, which is never read' => [
            'adversarial-key-info-with-garbage-decrypts.xml',
        ];
        yield 'a comment and whitespace inside the EncryptionMethod' => [
            'adversarial-encryption-method-with-comment-and-whitespace-decrypts.xml',
        ];
        yield 'the EncryptedData under another prefix of the same namespace' => [
            'adversarial-encrypted-data-under-another-prefix-decrypts.xml',
        ];
        yield 'Id attributes on the EncryptedData and the EncryptedKey, unique in the document' => [
            'adversarial-id-attributes-on-encrypted-data-and-key-decrypts.xml',
        ];
        yield 'MimeType and Encoding attributes, which the model does not read' => [
            'adversarial-mime-type-and-encoding-attributes-decrypts.xml',
        ];
        yield 'xml:space on the EncryptedData' => ['adversarial-xml-space-on-encrypted-data-decrypts.xml'];
    }

    /**
     * Section 9.7, E-4: an assertion holding an EncryptedData decrypts to that assertion, its EncryptedData left
     * as it is; the consumer decrypts it when it decides to, here with the same key, since it is the vector's.
     */
    #[Test]
    public function itDecryptsAnAssertionHoldingAnEncryptedDataItDoesNotTouch(): void
    {
        // Given
        $document = Loaded::fixture('behaviour/adversarial-nested-encrypted-data-decrypts.xml');

        // When
        $outer = $this->decryptor->decrypt(Encrypted::dataOf($document), $this->key);

        // Then
        $advice = Children::one($outer->root(), new Name(Stack::SAML_ASSERTION, 'Advice'));
        $inner = Children::one(
            Children::one($advice, new Name(Stack::SAML_ASSERTION, 'EncryptedAssertion')),
            new Name(Stack::XMLENC, 'EncryptedData'),
        );
        static::assertSame(256, strlen(EncryptedData::of($inner)->key->cipherValue));
        $decrypted = $this->decryptor->decrypt($inner, $this->key);
        static::assertSame($decrypted->root(), $decrypted->elementById('_assertion-d4e5f6'));
        static::assertNull(Children::optional($decrypted->root(), new Name(Stack::SAML_ASSERTION, 'Advice')));
    }

    /**
     * Section 9.7, E-11: keys of every wrong kind, refused with the rule named and nothing of the PEM.
     */
    #[Test]
    #[DataProvider('provideWrongKinds')]
    public function itRefusesAKeyOfTheWrongKind(string $side, string $file, string $message): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs($message);

        // When
        match ($side) {
            'private' => PrivateDecryptionKey::fromPem($pem),
            default => PeerKey::fromPublicKeyPem($pem),
        };
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideWrongKinds(): iterable
    {
        $noPrivate = 'The PEM holds no private key, or the passphrase is wrong (E-11).';
        $noPublic = 'The PEM holds no certificate and no public key (E-11).';

        yield 'a public key as the decryption key' => ['private', 'keys/test-signing-public-key.pem', $noPrivate];
        yield 'a certificate as the decryption key' => ['private', 'keys/ec-p256-certificate.pem', $noPrivate];
        yield 'a private key as the peer key' => ['peer', 'keys/weak-rsa-1024-key.pem', $noPublic];
        yield 'a DSA private key as the peer key' => ['peer', 'keys/dsa-2048-key.pem', $noPublic];
        yield 'an EC certificate as the peer key' => [
            'peer',
            'keys/ec-p256-certificate.pem',
            'A peer key is RSA of at least 2048 bits (E-11).',
        ];
    }

    /**
     * §9.3 row 17, E-12: every refusal of the pass ends with the rule in parentheses and carries no URI, no ID and
     * no base64; every failure is the one message.
     */
    #[Test]
    public function itsRefusalsNameTheRuleAndNothingOfTheInput(): void
    {
        // Given
        $messages = [DecryptionFailed::MESSAGE];
        foreach (self::provideRefusedAttempts() as [, , $message]) {
            $messages[] = $message;
        }
        foreach (self::provideWrongKinds() as [, , $message]) {
            $messages[] = $message;
        }
        static::assertGreaterThan(15, count($messages));

        // When / Then
        foreach ($messages as $message) {
            static::assertMatchesRegularExpression('~\((E-\d+(, E-\d+)*|I-\d+|section [0-9.]+)\)\.$~', $message);
            static::assertStringNotContainsString('http', $message);
            static::assertStringNotContainsString('_assertion', $message);
            static::assertDoesNotMatchRegularExpression('~[A-Za-z0-9+/]{20}~', $message);
        }
    }
}
