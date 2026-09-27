<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Base64;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_repeat;
use function strlen;
use Throwable;

/**
 * Section 5.3, E-5: the xenc:EncryptedData element read strictly, nothing decrypted; every shape of section 9.2
 * the model refuses, with its rule named (E-12).
 */
final class EncryptedDataTest extends TestCase
{
    /**
     * Section 5.3, §9.1 row 1: the encrypted assertion of the vector, every field where the section says it is.
     */
    #[Test]
    public function itReadsTheEncryptedDataOfTheVector(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);

        // When
        $data = EncryptedData::of($element);

        // Then
        static::assertSame($element, $data->element);
        static::assertSame(ContentAlgorithm::Aes256Gcm, $data->algorithm);
        static::assertSame(Encrypted::keyOf($document), $data->key->element);
        static::assertSame(OaepHash::Sha1, $data->key->transport->hash);
        static::assertSame(256, strlen($data->key->cipherValue));
        static::assertGreaterThan(EncryptedData::MIN_CIPHER_BYTES, strlen($data->cipherValue));
    }

    /**
     * §9.1 rows 1 to 7: every vector reads, with its content algorithm and the hash of its key transport.
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itReadsEveryVector(string $fixture, ContentAlgorithm $algorithm, OaepHash $hash): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);

        // When
        $data = EncryptedData::of(Encrypted::dataOf($document));

        // Then
        static::assertSame($algorithm, $data->algorithm);
        static::assertSame($hash, $data->key->transport->hash);
    }

    /**
     * @return iterable<string, array{string, ContentAlgorithm, OaepHash}>
     */
    public static function provideVectors(): iterable
    {
        yield 'row 1, aes256-gcm' => [
            'response-encrypted-assertion-aes256-gcm.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha1,
        ];
        yield 'row 2, aes128-gcm' => [
            'response-encrypted-assertion-aes128-gcm.xml',
            ContentAlgorithm::Aes128Gcm,
            OaepHash::Sha1,
        ];
        yield 'row 3, the key without KeyInfo' => [
            'response-encrypted-assertion-keyinfo-absent.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha1,
        ];
        yield 'row 4, the DigestMethod of SHA-1 under rsa-oaep-mgf1p' => [
            'response-encrypted-assertion-mgf1p-digest-sha1.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha1,
        ];
        yield 'row 5, rsa-oaep with SHA-256' => [
            'response-encrypted-assertion-rsa-oaep-sha256.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha256,
        ];
        yield 'row 6, the signed assertion' => [
            'response-encrypted-signed-assertion.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha1,
        ];
        yield 'row 7, the assertion holding a comment' => [
            'response-encrypted-assertion-with-comment.xml',
            ContentAlgorithm::Aes256Gcm,
            OaepHash::Sha1,
        ];
    }

    /**
     * §9.2 rows 1 to 15, 17 and 18, E-1, E-2, E-5, E-7, E-13: every shape the model refuses, with the rule named
     * and never the input (E-12).
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedShapes')]
    public function itRefusesAShapeOfTheHostileCorpus(string $fixture, string $exception, string $message): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        EncryptedData::of($element);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function provideRefusedShapes(): iterable
    {
        $content = 'The content algorithm is not AES-128-GCM or AES-256-GCM (E-1).';
        $notOaep = 'The key transport is not RSA-OAEP: PKCS#1 v1.5, key wrapping and key agreement are refused by name (E-1).';
        $differ = 'The DigestMethod and the MGF of rsa-oaep name different hashes, which PHP cannot express (E-1).';
        $mgf1pChild = 'An EncryptionMethod of rsa-oaep-mgf1p holds nothing but a DigestMethod (E-5).';
        $type = 'The Type of an EncryptedData is Element: the plaintext is a whole element or nothing (E-5).';
        $otherChild = 'An EncryptedData holds a child other than EncryptionMethod, KeyInfo and CipherData (E-5).';
        $otherKeyChild = 'An EncryptedKey holds a child other than EncryptionMethod, KeyInfo and CipherData (E-5).';
        $oneKey = 'The KeyInfo of an EncryptedData holds exactly one EncryptedKey (E-5).';
        $base64 = 'A CipherValue holds a character outside the base64 alphabet or is empty (E-7).';
        $keyBound = 'The cipher value of an EncryptedKey is not between 256 and maxEncryptedKeyBytes, 1024 bytes (E-13).';
        $names = 'An EncryptionMethod names its Algorithm (E-5).';

        yield 'row 1, aes128-cbc' => ['content-aes128-cbc-refused.xml', UnknownContentAlgorithm::class, $content];
        yield 'row 1, aes256-cbc' => ['content-aes256-cbc-refused.xml', UnknownContentAlgorithm::class, $content];
        yield 'row 1, tripledes-cbc' => ['content-tripledes-cbc-refused.xml', UnknownContentAlgorithm::class, $content];
        yield 'row 2, aes192-gcm' => ['content-aes192-gcm-refused.xml', UnknownContentAlgorithm::class, $content];
        yield 'row 3, rsa-1_5' => ['key-transport-rsa-1-5-refused.xml', UnknownKeyTransport::class, $notOaep];
        yield 'row 4, kw-aes256' => ['key-transport-kw-aes256-refused.xml', UnknownKeyTransport::class, $notOaep];
        yield 'row 5, rsa-oaep with a DigestMethod of SHA-256 and an MGF of SHA-1' => [
            'rsa-oaep-digest-sha256-mgf-sha1-refused.xml',
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'row 6, rsa-oaep with a DigestMethod of SHA-256 and no MGF' => [
            'rsa-oaep-digest-sha256-no-mgf-refused.xml',
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'row 7, rsa-oaep-mgf1p with a DigestMethod of SHA-256' => [
            'mgf1p-digest-sha256-refused.xml',
            UnknownKeyTransport::class,
            'The DigestMethod of rsa-oaep-mgf1p names a hash other than SHA-1, the one MGF1 uses under that name (E-1).',
        ];
        yield 'row 8, rsa-oaep-mgf1p with an MGF' => [
            'mgf1p-with-mgf-refused.xml',
            MalformedEncryption::class,
            $mgf1pChild,
        ];
        yield 'row 9, rsa-oaep-mgf1p with an OAEPparams' => [
            'mgf1p-oaepparams-refused.xml',
            MalformedEncryption::class,
            $mgf1pChild,
        ];
        yield 'row 10, a Type of Content' => ['type-content-refused.xml', MalformedEncryption::class, $type];
        yield 'row 10, no Type' => ['type-absent-refused.xml', MalformedEncryption::class, $type];
        yield 'row 11, a CipherReference' => [
            'cipher-reference-refused.xml',
            MalformedEncryption::class,
            'A CipherData holds nothing but a CipherValue, never a CipherReference (E-5).',
        ];
        yield 'row 12, an EncryptionProperties' => [
            'encryption-properties-refused.xml',
            MalformedEncryption::class,
            $otherChild,
        ];
        yield 'row 12, a ReferenceList inside the key' => [
            'reference-list-inside-key-refused.xml',
            MalformedEncryption::class,
            $otherKeyChild,
        ];
        yield 'row 12, a CarriedKeyName' => [
            'carried-key-name-refused.xml',
            MalformedEncryption::class,
            $otherKeyChild,
        ];
        yield 'row 13, two EncryptedKey' => ['two-encrypted-keys-refused.xml', MalformedEncryption::class, $oneKey];
        yield 'row 13, no EncryptedKey' => ['no-encrypted-key-refused.xml', MalformedEncryption::class, $oneKey];
        yield 'row 13, a KeyName in place of the EncryptedKey' => [
            'key-info-holding-a-key-name-refused.xml',
            MalformedEncryption::class,
            'The KeyInfo of an EncryptedData holds nothing but an EncryptedKey (E-5).',
        ];
        yield 'row 14, a KeySize' => [
            'key-size-refused.xml',
            MalformedEncryption::class,
            'The EncryptionMethod of an EncryptedData holds no child (E-5).',
        ];
        yield 'row 15, a character outside the alphabet' => [
            'cipher-value-outside-alphabet-refused.xml',
            MalformedEncryption::class,
            $base64,
        ];
        yield 'row 15, an empty cipher value' => [
            'cipher-value-empty-refused.xml',
            MalformedEncryption::class,
            $base64,
        ];
        yield 'row 17, a data cipher value of 28 bytes' => [
            'data-cipher-value-28-bytes-refused.xml',
            MalformedEncryption::class,
            'The cipher value of an EncryptedData holds an IV of 12 bytes, at least one byte of ciphertext and a tag of 16 bytes (E-2).',
        ];
        yield 'row 18, a key cipher value of 255 bytes' => [
            'key-cipher-value-255-bytes-refused.xml',
            LimitExceeded::class,
            $keyBound,
        ];
        yield 'row 18, a key cipher value of 1025 bytes' => [
            'key-cipher-value-1025-bytes-refused.xml',
            LimitExceeded::class,
            $keyBound,
        ];
        yield 'a content EncryptionMethod without Algorithm' => [
            'content-method-without-algorithm-refused.xml',
            MalformedEncryption::class,
            $names,
        ];
        yield 'a key EncryptionMethod without Algorithm' => [
            'key-method-without-algorithm-refused.xml',
            MalformedEncryption::class,
            $names,
        ];
        yield 'two EncryptionMethod' => [
            'two-encryption-methods-refused.xml',
            MalformedEncryption::class,
            'An EncryptedData holds exactly one EncryptionMethod (E-5).',
        ];
        yield 'no KeyInfo' => [
            'no-key-info-refused.xml',
            MalformedEncryption::class,
            'An EncryptedData holds exactly one KeyInfo (E-5).',
        ];
        yield 'two CipherData' => [
            'two-cipher-data-refused.xml',
            MalformedEncryption::class,
            'An EncryptedData holds exactly one CipherData (E-5).',
        ];
        yield 'the key without CipherData' => [
            'key-without-cipher-data-refused.xml',
            MalformedEncryption::class,
            'An EncryptedKey holds exactly one CipherData (E-5).',
        ];
        yield 'the key with two KeyInfo' => [
            'two-key-infos-in-the-key-refused.xml',
            MalformedEncryption::class,
            'An EncryptedKey holds at most one KeyInfo (E-5).',
        ];
    }

    /**
     * §9.3 row 17, E-12: every refusal of the corpus names its rule in parentheses and carries no URI.
     */
    #[Test]
    public function itsRefusalsNameTheRuleAndNeverTheInput(): void
    {
        foreach (self::provideRefusedShapes() as $name => [, , $message]) {
            // When / Then
            static::assertMatchesRegularExpression('~ \(E-\d+\)\.$~', $message, $name);
            static::assertStringNotContainsString('http', $message, $name);
            static::assertStringNotContainsString('=', $message, $name);
        }
    }

    /**
     * §9.2 row 16, E-13: a CipherValue text over maxCipherValueBytes, in a document the consumer's limits let
     * through, refused before it is decoded.
     */
    #[Test]
    public function itRefusesACipherValueTextOverTheBound(): void
    {
        // Given
        $bytes = preg_replace(
            '~(?<=\n)    <xenc:CipherValue>[^<]*</xenc:CipherValue>~',
            '    <xenc:CipherValue>' . str_repeat('A', Base64::MAX_TEXT_BYTES + 1) . '</xenc:CipherValue>',
            Fixtures::bytes('vectors/response-encrypted-assertion-aes256-gcm.xml'),
        );
        static::assertNotNull($bytes);
        $document = new Loader(Stack::idAttributes(), new Limits(maxBytes: 4_194_304))->load($bytes);
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A CipherValue is longer than maxCipherValueBytes, 2097152 bytes of text (E-13).');

        // When
        EncryptedData::of($element);
    }

    /**
     * E-5: the element is not an EncryptedData, an EncryptedAssertion here.
     */
    #[Test]
    public function itRefusesAnElementThatIsNotAnEncryptedData(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'EncryptedAssertion'));

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The element is not a xenc:EncryptedData (E-5).');

        // When
        EncryptedData::of($element);
    }

    /**
     * §9.2 row 34: a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAForeignElement(): void
    {
        // Given
        $foreign = Foreign::parse(Fixtures::bytes('vectors/encrypted-data-aes256-gcm.template.xml'));
        $element = $foreign->documentElement;
        static::assertNotNull($element);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        EncryptedData::of($element);
    }
}
