<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Limits;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use Beffroi\Xml\Tests\Enc\Support\UnwrappingKey;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Throwable;

/**
 * Section 6.1: decryption in order, the vectors of section 9.1 decrypted to a Document the consumer's Loader built
 * (E-4), every failing fixture of section 9.2 the one failure with the one message (E-3).
 */
final class DecryptorTest extends TestCase
{
    /**
     * §9.1 rows 1 to 4, 6 and 7, §9.3 row 1: every vector decrypts to a Document whose root is the assertion, its
     * ID indexed, its Issuer readable.
     */
    #[Test]
    #[DataProvider('provideVectors')]
    public function itDecryptsAVector(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);

        // When
        $decrypted = $this->decryptor()->decrypt(Encrypted::dataOf($document), $this->key());

        // Then
        $root = $decrypted->root();
        static::assertTrue(new Name(Stack::SAML_ASSERTION, 'Assertion')->matches($root));
        static::assertSame($root, $decrypted->elementById('_assertion-d4e5f6'));
        static::assertSame('https://idp.example.org', $this->issuerOf($decrypted));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideVectors(): iterable
    {
        yield 'row 1, aes256-gcm' => ['response-encrypted-assertion-aes256-gcm.xml'];
        yield 'row 2, aes128-gcm' => ['response-encrypted-assertion-aes128-gcm.xml'];
        yield 'row 3, the key without KeyInfo' => ['response-encrypted-assertion-keyinfo-absent.xml'];
        yield 'row 4, the DigestMethod of SHA-1 under rsa-oaep-mgf1p' => [
            'response-encrypted-assertion-mgf1p-digest-sha1.xml',
        ];
        yield 'row 6, the signed assertion' => ['response-encrypted-signed-assertion.xml'];
        yield 'row 7, the assertion holding a comment' => ['response-encrypted-assertion-with-comment.xml'];
    }

    /**
     * §9.1 row 5, section 13: rsa-oaep with SHA-256 decrypts where the RSA functions take a digest, PHP 8.5, and is
     * AlgorithmUnavailable on 8.4.
     */
    #[Test]
    public function itDecryptsUnderRsaOaepSha256WhereTheBuildTakesADigest(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-rsa-oaep-sha256.xml');
        $element = Encrypted::dataOf($document);
        if (! OaepHash::Sha256->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
            $this->expectExceptionMessageIs('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }

        // When
        $decrypted = $this->decryptor()->decrypt($element, $this->key());

        // Then
        static::assertSame('https://idp.example.org', $this->issuerOf($decrypted));
    }

    /**
     * §9.1 row 6: the signed assertion decrypted, then verified by Dsig with the test certificate: the round trip
     * of the stack, decrypt, load, verify.
     */
    #[Test]
    public function itDecryptsASignedAssertionThatDsigThenVerifies(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-signed-assertion.xml');
        $decrypted = $this->decryptor()->decrypt(Encrypted::dataOf($document), $this->key());
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $verified = $verifier->verify($decrypted->root(), $keys);

        // Then
        static::assertSame(SignatureAlgorithm::RsaSha256, $verified->algorithm);
        static::assertSame('https://idp.example.org', $this->issuerOf($verified->document));
    }

    /**
     * §9.1 row 7: the comment of the plaintext survives: the exclusive canonical form with comments of the NameID
     * holds it, and Text::of() reads around it.
     */
    #[Test]
    public function itKeepsTheCommentOfThePlaintext(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-with-comment.xml');

        // When
        $decrypted = $this->decryptor()->decrypt(Encrypted::dataOf($document), $this->key());

        // Then
        $nameId = Children::one(
            Children::one($decrypted->root(), new Name(Stack::SAML_ASSERTION, 'Subject')),
            new Name(Stack::SAML_ASSERTION, 'NameID'),
        );
        static::assertSame('user-0001', Text::of($nameId));
        static::assertStringContainsString(
            '<!-- a comment inside the plaintext -->',
            new Canonicalizer()->canonicalize($nameId, CanonicalizationMethod::ExclusiveWithComments)->bytes,
        );
    }

    /**
     * §9.3 row 2: decrypting the same element twice gives the same canonical bytes of the root.
     */
    #[Test]
    public function itDecryptsTheSameElementTwiceToTheSameBytes(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);
        $canonicalizer = new Canonicalizer();

        // When
        $first = $this->decryptor()->decrypt($element, $this->key());
        $second = $this->decryptor()->decrypt($element, $this->key());

        // Then
        static::assertSame(
            $canonicalizer->canonicalize($first->root(), CanonicalizationMethod::Exclusive)->bytes,
            $canonicalizer->canonicalize($second->root(), CanonicalizationMethod::Exclusive)->bytes,
        );
    }

    /**
     * §9.3 row 15, E-6: the port's answer is the session key. A key a test implements, answering what the PEM key
     * unwrapped, decrypts the vector; it is asked for the wrapped bytes of the EncryptedKey under the hash its
     * EncryptionMethod names.
     */
    #[Test]
    public function itUsesWhatThePortAnswers(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $data = EncryptedData::of(Encrypted::dataOf($document));
        $sessionKey = $this->key()->unwrap($data->key->cipherValue, OaepHash::Sha1);
        static::assertNotNull($sessionKey);
        $port = new UnwrappingKey($sessionKey);

        // When
        $decrypted = $this->decryptor()->decrypt($data->element, $port);

        // Then
        static::assertSame($data->key->cipherValue, $port->wrapped);
        static::assertSame(OaepHash::Sha1, $port->hash);
        static::assertSame('https://idp.example.org', $this->issuerOf($decrypted));
    }

    /**
     * §9.3 row 15, E-3: a port that answers null is the one failure.
     */
    #[Test]
    public function itFailsInTheOneWayWhenThePortAnswersNothing(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->decryptor()->decrypt($element, new UnwrappingKey(null));
    }

    /**
     * §9.2 rows 22 and 23 by the port, E-2: a session key of any length but the method's is the one failure, before
     * the primitive, which would have accepted the longer ones (section 13).
     */
    #[Test]
    #[TestWith([16], 'the length of the other method')]
    #[TestWith([31], 'one byte short')]
    #[TestWith([33], 'one byte long')]
    #[TestWith([64], 'twice the length')]
    public function itFailsInTheOneWayWhenThePortAnswersAKeyOfAnotherLength(int $length): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $this->decryptor()->decrypt($element, new UnwrappingKey(str_repeat("\x00", $length)));
    }

    /**
     * §9.2 rows 19 to 25 and 33, E-2, E-3: every failing fixture is the one failure with the one message, whatever
     * failed, and nothing else on the exception.
     */
    #[Test]
    #[DataProvider('provideFailingFixtures')]
    public function itFailsInTheOneWay(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // When
        try {
            $this->decryptor()->decrypt($element, $this->key());
        } catch (DecryptionFailed $failure) {
            // Then
            static::assertSame('The data could not be decrypted (E-3).', $failure->getMessage());
            static::assertSame(0, $failure->getCode());
            static::assertNull($failure->getPrevious());

            return;
        }

        static::fail('The decryptor accepted ' . $fixture);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFailingFixtures(): iterable
    {
        yield 'row 19, the key wrapped under the stranger\'s certificate' => [
            'encrypted-under-the-stranger-certificate-refused.xml',
        ];
        yield 'row 20, the key wrapped under PKCS#1 v1.5 padding' => ['key-wrapped-under-pkcs1-v1-5-refused.xml'];
        yield 'row 21, the wrapped key altered by one byte' => ['wrapped-key-altered-refused.xml'];
        yield 'row 22, a 32-byte session key under aes128-gcm' => [
            'session-key-32-bytes-declared-aes128-gcm-refused.xml',
        ];
        yield 'row 23, a 16-byte session key under aes256-gcm' => [
            'session-key-16-bytes-declared-aes256-gcm-refused.xml',
        ];
        yield 'row 24, the tag truncated to 15 bytes' => ['tag-truncated-refused.xml'];
        yield 'row 25, the tag altered' => ['tag-altered-refused.xml'];
        yield 'row 25, the ciphertext altered' => ['ciphertext-altered-refused.xml'];
        yield 'row 25, the IV altered' => ['iv-altered-refused.xml'];
    }

    /**
     * §9.2 rows 27, 28 and 30, E-4, E-9: an authentic ciphertext whose plaintext Core refuses is Core's named
     * refusal, since the plaintext goes through the consumer's Loader like everything else.
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedPlaintexts')]
    public function itHandsThePlaintextToTheConsumersLoader(string $fixture, string $exception): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException($exception);

        // When
        $this->decryptor()->decrypt($element, $this->key());
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>}>
     */
    public static function provideRefusedPlaintexts(): iterable
    {
        yield 'row 27, a DOCTYPE' => ['plaintext-with-doctype-refused.xml', DoctypeRefused::class];
        yield 'row 28, two root elements' => ['plaintext-with-two-roots-refused.xml', MalformedXml::class];
        yield 'no XML at all' => ['plaintext-not-xml-refused.xml', MalformedXml::class];
        yield 'row 30, the assertion without its namespace declaration' => [
            'plaintext-without-its-namespace-declaration-refused.xml',
            ParserDiagnostic::class,
        ];
    }

    /**
     * §9.2 row 29, E-4: the plaintext is bounded by the consumer's limits, not by this namespace.
     */
    #[Test]
    public function itBoundsThePlaintextByTheConsumersLimits(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $element = Encrypted::dataOf($document);
        $decryptor = new Decryptor(new Loader(Stack::idAttributes(), new Limits(maxBytes: 1024)));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The input is larger than maxBytes, 1024 bytes (I-7).');

        // When
        $decryptor->decrypt($element, $this->key());
    }

    /**
     * Section 6.1 step 2, E-5: the reading model refuses before any key is touched.
     */
    #[Test]
    public function itReadsTheStructureBeforeTouchingTheKey(): void
    {
        // Given
        $document = Loaded::fixture('hostile/content-aes128-cbc-refused.xml');
        $element = Encrypted::dataOf($document);
        $port = new UnwrappingKey(str_repeat("\x00", 32));

        // When
        try {
            $this->decryptor()->decrypt($element, $port);
        } catch (UnknownContentAlgorithm) {
            // Then
            static::assertNull($port->wrapped);

            return;
        }

        static::fail('The decryptor accepted a CBC method.');
    }

    /**
     * Section 6.1 step 3: the availability of the hash is checked before any key is touched; where the build takes
     * a digest, the port is asked under that hash.
     */
    #[Test]
    public function itChecksTheAvailabilityOfTheHashBeforeTouchingTheKey(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-rsa-oaep-sha256.xml');
        $element = Encrypted::dataOf($document);
        $port = new UnwrappingKey(null);

        // When
        try {
            $this->decryptor()->decrypt($element, $port);
        } catch (AlgorithmUnavailable) {
            // Then
            static::assertFalse(OaepHash::Sha256->isAvailable());
            static::assertNull($port->wrapped);

            return;
        } catch (DecryptionFailed) {
            static::assertTrue(OaepHash::Sha256->isAvailable());
            static::assertSame(OaepHash::Sha256, $port->hash);

            return;
        }

        static::fail('The decryptor decrypted with a port that answers nothing.');
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
        static::assertInstanceOf(Element::class, $element);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        $this->decryptor()->decrypt($element, new UnwrappingKey(null));
    }

    private function decryptor(): Decryptor
    {
        return new Decryptor(new Loader(Stack::idAttributes()));
    }

    private function key(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }

    private function issuerOf(Document $document): string
    {
        return Text::of(Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'Issuer')));
    }
}
