<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use function base64_decode;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\Internal\Pem;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use OpenSSLAsymmetricKey;
use function preg_replace;

/**
 * Whether the certificate is expired, revoked or trusted is the business of the metadata layer, which decided to
 * pass the key.
 */
final readonly class VerificationKey
{
    /**
     * Section 7, D-16
     */
    public const int MIN_BITS = 2048;

    private function __construct(
        private OpenSSLAsymmetricKey $handle,
    ) {
    }

    /**
     * @throws InvalidKey
     */
    public static function fromCertificatePem(string $pem): self
    {
        $certificate = Pem::block(
            $pem,
            'CERTIFICATE',
        ) ?? throw new InvalidKey('A certificate PEM is one block of type CERTIFICATE and nothing else (D-16).');

        return self::fromPublic(Pem::armour($certificate, 'CERTIFICATE'));
    }

    /**
     * OpenSSL refuses the bare base64 and reads the certificate once it is wrapped in the PEM armour (section 13).
     *
     * @throws InvalidKey
     */
    public static function fromCertificateBase64(string $base64): self
    {
        $certificate = base64_decode(preg_replace('~\s+~', '', $base64) ?? '', true);
        if ($certificate === false || $certificate === '') {
            throw new InvalidKey('A certificate is the base64 of its DER (D-16).');
        }

        return self::fromPublic(Pem::armour($certificate, 'CERTIFICATE'));
    }

    /**
     * @throws InvalidKey
     */
    public static function fromPublicKeyPem(string $pem): self
    {
        $key = Pem::block(
            $pem,
            'PUBLIC KEY',
        ) ?? throw new InvalidKey('A public key PEM is one block of type PUBLIC KEY and nothing else (D-16).');

        return self::fromPublic(Pem::armour($key, 'PUBLIC KEY'));
    }

    /**
     * @internal for Verifier only
     */
    public function handle(): OpenSSLAsymmetricKey
    {
        return $this->handle;
    }

    /**
     * @param string $pem one block the factories wrote themselves, never the consumer's string (D-16)
     *
     * @throws InvalidKey
     */
    private static function fromPublic(string $pem): self
    {
        $handle = openssl_pkey_get_public($pem);
        // OpenSSL leaves its diagnostics in a queue whatever the outcome; nothing of the stack reads them (D-13).

        if ($handle === false) {
            throw new InvalidKey('The PEM holds no certificate and no public key (D-16).');
        }
        $details = openssl_pkey_get_details($handle);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < self::MIN_BITS) {
            throw new InvalidKey('A verification key is RSA of at least 2048 bits (D-16).');
        }

        return new self($handle);
    }
}
