<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use function base64_decode;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use function chunk_split;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use OpenSSLAsymmetricKey;
use function preg_replace;

/**
 * A public key the consumer trusts, taken from the peer's metadata (D-7): the certificate's PEM, the base64 of
 * its DER as an X509Certificate element carries it, or a PEM public key. RSA of at least 2048 bits (D-16). It holds
 * an OpenSSLAsymmetricKey and nothing else, and exposes neither the PEM nor the modulus. Whether the certificate is
 * expired, revoked or trusted is the business of the metadata layer, which decided to pass the key.
 */
final readonly class VerificationKey
{
    /**
     * Section 7, D-16: what the interoperability targets sign with, and the floor of the profiles.
     */
    public const int MIN_BITS = 2048;

    private function __construct(
        private OpenSSLAsymmetricKey $handle,
    ) {
    }

    /**
     * @throws InvalidKey when the PEM holds no certificate, or a key that is not RSA of at least 2048 bits
     */
    public static function fromCertificatePem(string $pem): self
    {
        return self::fromPublic($pem);
    }

    /**
     * The content of an X509Certificate element: the base64 of the DER, whitespace tolerated. openssl reads the
     * certificate once it is wrapped in the PEM armour and refuses the bare base64 (measured, section 13).
     *
     * @throws InvalidKey
     */
    public static function fromCertificateBase64(string $base64): self
    {
        $clean = preg_replace('~\s+~', '', $base64) ?? '';
        if ($clean === '' || base64_decode($clean, true) === false) {
            throw new InvalidKey('A certificate is the base64 of its DER (D-16).');
        }

        return self::fromPublic(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split($clean, 64, "\n") . "-----END CERTIFICATE-----\n",
        );
    }

    /**
     * @throws InvalidKey when the PEM holds no public key, or one that is not RSA of at least 2048 bits
     */
    public static function fromPublicKeyPem(string $pem): self
    {
        return self::fromPublic($pem);
    }

    /**
     * @internal for Verifier only: the handle openssl_verify() takes (D-15)
     */
    public function handle(): OpenSSLAsymmetricKey
    {
        return $this->handle;
    }

    /**
     * @throws InvalidKey
     */
    private static function fromPublic(string $pem): self
    {
        $handle = openssl_pkey_get_public($pem);
        // openssl leaves its diagnostics in a queue whatever the outcome; nothing of the stack reads them (D-13)

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
