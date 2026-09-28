<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use function implode;
use function openssl_pkey_get_details;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_starts_with;

/**
 * Section 5.2, D-16: a trusted key from a certificate's PEM, from the base64 of its DER, or from a public key's
 * PEM; RSA of at least 2048 bits, and nothing else.
 */
final class VerificationKeyTest extends TestCase
{
    #[Test]
    public function itReadsACertificatePem(): void
    {
        // When
        $key = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));

        // Then
        $details = openssl_pkey_get_details($key->handle());
        static::assertNotFalse($details);
        static::assertSame(2048, $details['bits']);
    }

    /**
     * §9.3 row 16, section 13: the base64 of an X509Certificate element, line breaks inside, as a peer's metadata
     * carries it.
     */
    #[Test]
    public function itReadsTheBase64OfACertificate(): void
    {
        // Given
        $pem = Fixtures::bytes('keys/test-signing-certificate.pem');
        $base64 = preg_replace('~-----[A-Z ]+-----~', '', $pem);
        static::assertNotNull($base64);
        $reference = openssl_pkey_get_details(VerificationKey::fromCertificatePem($pem)->handle());
        static::assertNotFalse($reference);

        // When
        $key = VerificationKey::fromCertificateBase64("\n  " . $base64 . "\n  ");

        // Then
        $details = openssl_pkey_get_details($key->handle());
        static::assertNotFalse($details);
        static::assertSame($reference['key'], $details['key']);
    }

    #[Test]
    public function itReadsAPublicKeyPem(): void
    {
        // Given
        $details = openssl_pkey_get_details(
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'))->handle(),
        );
        static::assertNotFalse($details);

        $pem = $details['key'];
        static::assertIsString($pem);

        // When
        $key = VerificationKey::fromPublicKeyPem($pem);

        // Then
        $again = openssl_pkey_get_details($key->handle());
        static::assertNotFalse($again);
        static::assertSame($pem, $again['key']);
        static::assertTrue(str_starts_with($pem, '-----BEGIN PUBLIC KEY-----'));
    }

    /**
     * D-16: what is not base64 is not a certificate.
     */
    #[Test]
    #[TestWith(['not base64!'], 'a character outside the alphabet')]
    #[TestWith([''], 'empty')]
    #[TestWith(["  \n"], 'whitespace only')]
    public function itRefusesWhatIsNotTheBase64OfACertificate(string $base64): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A certificate is the base64 of its DER (D-16).');

        // When
        VerificationKey::fromCertificateBase64($base64);
    }

    /**
     * D-16: one block of type CERTIFICATE whose bytes openssl cannot read as a certificate.
     */
    #[Test]
    public function itRefusesACertificateBlockAroundGarbage(): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no certificate and no public key (D-16).');

        // When
        VerificationKey::fromCertificatePem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    }

    /**
     * §9.2 row 41, D-16: what is not exactly one block of type CERTIFICATE never reaches openssl, a path to a file
     * that holds one first.
     */
    #[Test]
    #[DataProvider('provideWhatIsNotOneCertificateBlock')]
    public function itRefusesWhatIsNotOneCertificateBlock(string $pem): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A certificate PEM is one block of type CERTIFICATE and nothing else (D-16).');

        // When
        VerificationKey::fromCertificatePem($pem);
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
        yield 'text before the armour' => ['issued to the IdP' . "\n" . $certificate];
        yield 'two certificates' => [$certificate . Fixtures::bytes('keys/stranger-certificate.pem')];
        yield 'a public key' => [self::publicKeyPem()];
        yield 'a private key' => [Fixtures::bytes('keys/test-signing-key.pem')];
    }

    /**
     * §9.2 row 41, D-16: what is not exactly one block of type PUBLIC KEY never reaches openssl.
     */
    #[Test]
    #[DataProvider('provideWhatIsNotOnePublicKeyBlock')]
    public function itRefusesWhatIsNotOnePublicKeyBlock(string $pem): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A public key PEM is one block of type PUBLIC KEY and nothing else (D-16).');

        // When
        VerificationKey::fromPublicKeyPem($pem);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotOnePublicKeyBlock(): iterable
    {
        yield 'a certificate' => [Fixtures::bytes('keys/test-signing-certificate.pem')];
        yield 'a file:// path' => ['file://' . Fixtures::path('keys/test-signing-certificate.pem')];
        yield 'two public keys' => [self::publicKeyPem() . self::publicKeyPem()];
    }

    /**
     * D-16: the base64 of something that is not a certificate.
     */
    #[Test]
    public function itRefusesTheBase64OfSomethingThatIsNotACertificate(): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('The PEM holds no certificate and no public key (D-16).');

        // When
        VerificationKey::fromCertificateBase64('AAAA');
    }

    /**
     * §9.2 row 35, D-16: a 1024-bit RSA key, then an EC key.
     */
    #[Test]
    #[TestWith(['weak-rsa-1024-certificate.pem'], 'RSA-1024')]
    #[TestWith(['ec-p256-certificate.pem'], 'EC P-256')]
    public function itRefusesAWeakOrNonRsaCertificate(string $file): void
    {
        // Given
        $pem = Fixtures::bytes('keys/' . $file);

        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs('A verification key is RSA of at least 2048 bits (D-16).');

        // When
        VerificationKey::fromCertificatePem($pem);
    }

    /**
     * The PEM of the test key's public half, as openssl writes it.
     */
    private static function publicKeyPem(): string
    {
        $details = openssl_pkey_get_details(
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'))->handle(),
        );
        static::assertNotFalse($details);
        static::assertIsString($details['key']);

        return $details['key'];
    }

    /**
     * D-13: a refusal of the key carries nothing of the PEM.
     */
    #[Test]
    public function itsRefusalCarriesNothingOfThePem(): void
    {
        // Given
        $pem = implode("\n", ['-----BEGIN CERTIFICATE-----', 'secretlookingbase64==', '-----END CERTIFICATE-----']);

        // When
        try {
            VerificationKey::fromCertificatePem($pem);
            static::fail('The PEM holds no certificate.');
        } catch (InvalidKey $refused) {
            // Then
            static::assertStringNotContainsString('secret', $refused->getMessage());
        }
    }
}
