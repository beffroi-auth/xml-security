<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function openssl_error_string;
use function str_repeat;
use function strlen;

/**
 * Section 5.2, E-3, E-11: the decryption key on a PEM, RSA of at least 2048 bits, answering the session key or
 * null and never why.
 */
final class PrivateDecryptionKeyTest extends TestCase
{
    /**
     * Section 5.2: the test key unwraps the session key of a vector, whose length is the method's.
     */
    #[Test]
    #[TestWith(['response-encrypted-assertion-aes256-gcm.xml', 32], 'aes256-gcm')]
    #[TestWith(['response-encrypted-assertion-aes128-gcm.xml', 16], 'aes128-gcm')]
    #[TestWith(['response-encrypted-assertion-mgf1p-digest-sha1.xml', 32], 'the DigestMethod of SHA-1')]
    public function itUnwrapsTheSessionKeyOfAVector(string $fixture, int $length): void
    {
        // Given
        $document = Loaded::fixture('vectors/' . $fixture);
        $data = EncryptedData::of(Encrypted::dataOf($document));
        $key = $this->key();

        // When
        $sessionKey = $key->unwrap($data->key->cipherValue, $data->key->transport->hash);

        // Then
        static::assertNotNull($sessionKey);
        static::assertSame($length, strlen($sessionKey));
    }

    /**
     * §9.1 row 5, section 13: under SHA-256 where the RSA functions take a digest, PHP 8.5; AlgorithmUnavailable
     * on 8.4, before the key is touched.
     */
    #[Test]
    public function itUnwrapsUnderSha256WhereTheBuildTakesADigest(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-rsa-oaep-sha256.xml');
        $data = EncryptedData::of(Encrypted::dataOf($document));
        if (! OaepHash::Sha256->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
            $this->expectExceptionMessageIs('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }

        // When
        $sessionKey = $this->key()->unwrap($data->key->cipherValue, OaepHash::Sha256);

        // Then
        static::assertNotNull($sessionKey);
        static::assertSame(32, strlen($sessionKey));
    }

    /**
     * §9.2 rows 19, 20 and 21, E-3: what does not unwrap is null, never why: the stranger's transport, PKCS#1 v1.5
     * padding, a blob altered by one byte, a blob of the wrong length, nothing at all.
     */
    #[Test]
    #[TestWith(['hostile/encrypted-under-the-stranger-certificate-refused.xml'], 'the stranger\'s certificate')]
    #[TestWith(['hostile/key-wrapped-under-pkcs1-v1-5-refused.xml'], 'PKCS#1 v1.5 padding')]
    #[TestWith(['hostile/wrapped-key-altered-refused.xml'], 'one byte altered')]
    public function itAnswersNullForAWrappedKeyThatDoesNotUnwrap(string $fixture): void
    {
        // Given
        $document = Loaded::fixture($fixture);
        $data = EncryptedData::of(Encrypted::dataOf($document));

        // When / Then
        static::assertNull($this->key()->unwrap($data->key->cipherValue, OaepHash::Sha1));
    }

    /**
     * §9.2 row 39, E-3: a wrapped key that does not unwrap leaves nothing in OpenSSL's error queue, which would say
     * which step failed to whoever reads it.
     */
    #[Test]
    #[TestWith(['hostile/key-wrapped-under-pkcs1-v1-5-refused.xml'], 'PKCS#1 v1.5 padding')]
    #[TestWith(['hostile/wrapped-key-altered-refused.xml'], 'one byte altered')]
    public function itLeavesNothingInOpensslsErrorQueue(string $fixture): void
    {
        // Given
        $document = Loaded::fixture($fixture);
        $data = EncryptedData::of(Encrypted::dataOf($document));
        $key = $this->key();

        // When
        $sessionKey = $key->unwrap($data->key->cipherValue, OaepHash::Sha1);

        // Then
        static::assertNull($sessionKey);
        static::assertFalse(openssl_error_string());
    }

    #[Test]
    #[TestWith([256], 'zeros of the modulus length')]
    #[TestWith([255], 'one byte short')]
    #[TestWith([257], 'one byte long')]
    #[TestWith([1], 'one byte')]
    #[TestWith([0], 'nothing')]
    public function itAnswersNullForABlobThatIsNoTransport(int $length): void
    {
        // When / Then
        static::assertNull($this->key()->unwrap(str_repeat("\x00", $length), OaepHash::Sha1));
    }

    /**
     * Section 13: a blob wrapped under SHA-1 does not unwrap under SHA-256, where the build takes a digest.
     */
    #[Test]
    public function itAnswersNullUnderAnotherHash(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $data = EncryptedData::of(Encrypted::dataOf($document));
        if (! OaepHash::Sha256->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
        }

        // When / Then
        static::assertNull($this->key()->unwrap($data->key->cipherValue, OaepHash::Sha256));
    }

    /**
     * Section 5.2: a passphrase-protected PEM opens with its passphrase; it is another key, which unwraps nothing
     * of the vectors.
     */
    #[Test]
    public function itReadsAnEncryptedPemWithItsPassphrase(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-encrypted-assertion-aes256-gcm.xml');
        $data = EncryptedData::of(Encrypted::dataOf($document));

        // When
        $key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/encrypted-rsa-2048-key.pem'), 'test-passphrase');

        // Then
        static::assertNull($key->unwrap($data->key->cipherValue, OaepHash::Sha1));
    }

    /**
     * E-11: a PEM that gives no private key.
     */
    #[Test]
    #[TestWith(['keys/encrypted-rsa-2048-key.pem', 'wrong'], 'a wrong passphrase')]
    #[TestWith(['keys/encrypted-rsa-2048-key.pem', null], 'no passphrase')]
    #[TestWith(['keys/test-signing-certificate.pem', null], 'a certificate, which holds no private key')]
    public function itRefusesAPemThatGivesNoPrivateKey(string $file, ?string $passphrase): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no private key, or the passphrase is wrong (E-11).');

        // When
        PrivateDecryptionKey::fromPem($pem, $passphrase);
    }

    /**
     * §9.2 row 38, E-11: a path is not a PEM, even one OpenSSL would open and read the key from.
     */
    #[Test]
    public function itRefusesAPathToAKeyFile(): void
    {
        // Given
        $path = 'file://' . Fixtures::path('keys/test-signing-key.pem');

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no private key, or the passphrase is wrong (E-11).');

        // When
        PrivateDecryptionKey::fromPem($path);
    }

    /**
     * §9.2 row 31, E-11: a key under 2048 bits, or not RSA.
     */
    #[Test]
    #[TestWith(['keys/weak-rsa-1024-key.pem'], 'RSA-1024')]
    #[TestWith(['keys/ec-p256-key.pem'], 'EC P-256')]
    #[TestWith(['keys/dsa-2048-key.pem'], 'DSA-2048')]
    public function itRefusesAWeakOrNonRsaKey(string $file): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A decryption key is RSA of at least 2048 bits (E-11).');

        // When
        PrivateDecryptionKey::fromPem($pem);
    }

    /**
     * E-12: the refusal carries nothing of the PEM.
     */
    #[Test]
    public function itsRefusalCarriesNothingOfThePem(): void
    {
        // Given
        $pem = "-----BEGIN PRIVATE KEY-----\nsecret-material-that-must-not-leak\n-----END PRIVATE KEY-----\n";

        // When
        try {
            PrivateDecryptionKey::fromPem($pem, 'the-passphrase');
        } catch (InvalidKey $refusal) {
            // Then
            static::assertStringNotContainsString('secret-material', $refusal->getMessage());
            static::assertStringNotContainsString('the-passphrase', $refusal->getMessage());

            return;
        }

        static::fail('A PEM holding no key was accepted.');
    }

    private function key(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }
}
