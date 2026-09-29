<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use function ini_get;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use SensitiveParameterValue;
use function str_repeat;
use function strlen;

/**
 * Section 5.2, E-11: the peer's encryption certificate, read three ways, RSA of at least 2048 bits, wrapping a
 * session key the matching private key unwraps.
 */
final class PeerKeyTest extends TestCase
{
    /**
     * Section 5.2: the certificate's PEM wraps a session key the test key unwraps.
     */
    #[Test]
    public function itReadsACertificatePemAndWrapsWhatThePrivateKeyUnwraps(): void
    {
        // Given
        $peer = PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));
        $sessionKey = str_repeat("\x2a", 32);

        // When
        $wrapped = $peer->wrap($sessionKey, OaepHash::Sha1);

        // Then
        static::assertSame(256, strlen($wrapped));
        static::assertSame($sessionKey, $this->privateKey()->unwrap($wrapped, OaepHash::Sha1));
    }

    /**
     * §9.3 row 16: the content of an X509Certificate element, its line breaks included.
     */
    #[Test]
    public function itReadsACertificateBase64WithLineBreaks(): void
    {
        // Given
        $base64 = preg_replace('~-----[A-Z ]+-----~', '', Fixtures::bytes('keys/test-signing-certificate.pem'));
        static::assertNotNull($base64);
        static::assertStringContainsString("\n", (string) $base64);
        $sessionKey = str_repeat("\x2b", 16);

        // When
        $peer = PeerKey::fromCertificateBase64($base64);

        // Then
        static::assertSame($sessionKey, $this->privateKey()->unwrap(
            $peer->wrap($sessionKey, OaepHash::Sha1),
            OaepHash::Sha1,
        ));
    }

    /**
     * Section 5.2: a PEM public key, the one of the test certificate.
     */
    #[Test]
    public function itReadsAPublicKeyPem(): void
    {
        // Given
        $sessionKey = str_repeat("\x2c", 32);

        // When
        $peer = PeerKey::fromPublicKeyPem(Fixtures::bytes('keys/test-signing-public-key.pem'));

        // Then
        static::assertSame($sessionKey, $this->privateKey()->unwrap(
            $peer->wrap($sessionKey, OaepHash::Sha1),
            OaepHash::Sha1,
        ));
    }

    /**
     * Section 13: under SHA-256 where the build takes a digest, the private key unwraps under SHA-256 and not under
     * SHA-1; AlgorithmUnavailable on 8.4.
     */
    #[Test]
    public function itWrapsUnderSha256WhereTheBuildTakesADigest(): void
    {
        // Given
        $peer = PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));
        $sessionKey = str_repeat("\x2d", 32);
        if (! OaepHash::Sha256->isAvailable()) {
            $this->expectException(AlgorithmUnavailable::class);
            $this->expectExceptionMessageIs('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }

        // When
        $wrapped = $peer->wrap($sessionKey, OaepHash::Sha256);

        // Then
        static::assertSame($sessionKey, $this->privateKey()->unwrap($wrapped, OaepHash::Sha256));
        static::assertNull($this->privateKey()->unwrap($wrapped, OaepHash::Sha1));
    }

    /**
     * E-11: what is not base64 is not a certificate.
     */
    #[Test]
    #[TestWith(['not base64 at all!'], 'characters outside the alphabet')]
    #[TestWith([''], 'empty')]
    #[TestWith(["\n  \n"], 'whitespace only')]
    public function itRefusesACertificateThatIsNotBase64(string $base64): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A certificate is the base64 of its DER (E-11).');

        // When
        PeerKey::fromCertificateBase64($base64);
    }

    /**
     * E-11: base64 that is no certificate, and a PEM that holds no public key.
     */
    #[Test]
    public function itRefusesBase64ThatIsNoCertificate(): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no certificate and no public key (E-11).');

        // When
        PeerKey::fromCertificateBase64('AAECAwQFBgcICQ==');
    }

    /**
     * E-11: one block of type CERTIFICATE whose bytes openssl cannot read as a certificate.
     */
    #[Test]
    public function itRefusesACertificateBlockAroundGarbage(): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no certificate and no public key (E-11).');

        // When
        PeerKey::fromCertificatePem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    }

    /**
     * §9.2 row 41, E-11: what is not exactly one block of type CERTIFICATE never reaches openssl, a path to a file
     * that holds one first.
     */
    #[Test]
    #[DataProvider('provideWhatIsNotOneCertificateBlock')]
    public function itRefusesWhatIsNotOneCertificateBlock(string $pem): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A certificate PEM is one block of type CERTIFICATE and nothing else (E-11).');

        // When
        PeerKey::fromCertificatePem($pem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotOneCertificateBlock(): iterable
    {
        $certificate = Fixtures::bytes('keys/test-signing-certificate.pem');

        yield 'plain text' => ['not a pem'];
        yield 'empty' => [''];
        yield 'a file:// path to a certificate' => ['file://' . Fixtures::path('keys/test-signing-certificate.pem')];
        yield 'text before the armour' => ['issued to the SP' . "\n" . $certificate];
        yield 'two certificates' => [Fixtures::bytes('keys/stranger-certificate.pem') . $certificate];
        yield 'a public key' => [Fixtures::bytes('keys/test-signing-public-key.pem')];
        yield 'a private key' => [Fixtures::bytes('keys/test-signing-key.pem')];
    }

    /**
     * §9.2 row 41, E-11: what is not exactly one block of type PUBLIC KEY never reaches openssl.
     */
    #[Test]
    #[DataProvider('provideWhatIsNotOnePublicKeyBlock')]
    public function itRefusesWhatIsNotOnePublicKeyBlock(string $pem): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A public key PEM is one block of type PUBLIC KEY and nothing else (E-11).');

        // When
        PeerKey::fromPublicKeyPem($pem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotOnePublicKeyBlock(): iterable
    {
        $publicKey = Fixtures::bytes('keys/test-signing-public-key.pem');

        yield 'a certificate' => [Fixtures::bytes('keys/test-signing-certificate.pem')];
        yield 'a file:// path' => ['file://' . Fixtures::path('keys/test-signing-public-key.pem')];
        yield 'two public keys' => [$publicKey . $publicKey];
    }

    /**
     * E-12: the session key given to wrap() stays out of the trace of its failure, a key too long for OAEP.
     */
    #[Test]
    public function itKeepsTheSessionKeyOutOfTheTrace(): void
    {
        // Given
        if (ini_get('zend.exception_ignore_args') === '1') {
            static::markTestSkipped('This build leaves the arguments out of every trace.');
        }
        $peer = PeerKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));

        // When
        try {
            $peer->wrap(str_repeat('k', 232), OaepHash::Sha1);
            static::fail('A key too long for OAEP does not wrap.');
        } catch (EncryptionFailed $failure) {
            // Then
            static::assertInstanceOf(SensitiveParameterValue::class, $failure->getTrace()[0]['args'][0] ?? null);
        }
    }

    /**
     * §9.2 row 32, E-11: a certificate of 1024 bits, then an EC one.
     */
    #[Test]
    #[TestWith(['keys/weak-rsa-1024-certificate.pem'], 'RSA-1024')]
    #[TestWith(['keys/ec-p256-certificate.pem'], 'EC P-256')]
    public function itRefusesAWeakOrNonRsaCertificate(string $file): void
    {
        // Given
        $pem = Fixtures::bytes($file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A peer key is RSA of at least 2048 bits (E-11).');

        // When
        PeerKey::fromCertificatePem($pem);
    }

    /**
     * E-12: the refusal carries nothing of the PEM.
     */
    #[Test]
    public function itsRefusalCarriesNothingOfThePem(): void
    {
        // Given
        $pem = "-----BEGIN CERTIFICATE-----\nmaterial-that-must-not-leak\n-----END CERTIFICATE-----\n";

        // When
        try {
            PeerKey::fromCertificatePem($pem);
        } catch (InvalidKey $refusal) {
            // Then
            static::assertStringNotContainsString('material-that-must-not-leak', $refusal->getMessage());

            return;
        }

        static::fail('A PEM holding no certificate was accepted.');
    }

    private function privateKey(): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));
    }
}
