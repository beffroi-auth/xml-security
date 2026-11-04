<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use function base64_decode;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\Internal\Pem;
use function is_string;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_OAEP_PADDING;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_public_encrypt;
use OpenSSLAsymmetricKey;
use function preg_replace;
use SensitiveParameter;

/**
 * Section 5.2, E-10, E-11: expiry, revocation and trust are left to the metadata layer that passed the key.
 */
final readonly class PeerKey
{
    /**
     * Section 7, E-11
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
        ) ?? throw new InvalidKey('A certificate PEM is one block of type CERTIFICATE and nothing else (E-11).');

        return self::fromPublic(Pem::armour($certificate, 'CERTIFICATE'));
    }

    /**
     * OpenSSL refuses the bare base64 of a DER, so the certificate is read once armoured as a PEM.
     *
     * @throws InvalidKey
     */
    public static function fromCertificateBase64(string $base64): self
    {
        $certificate = base64_decode(preg_replace('~\s+~', '', $base64) ?? '', true);
        if ($certificate === false || $certificate === '') {
            throw new InvalidKey('A certificate is the base64 of its DER (E-11).');
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
        ) ?? throw new InvalidKey('A public key PEM is one block of type PUBLIC KEY and nothing else (E-11).');

        return self::fromPublic(Pem::armour($key, 'PUBLIC KEY'));
    }

    /**
     * Section 6.2 step 5
     *
     * @internal for Encryptor only (E-10)
     *
     * @throws AlgorithmUnavailable
     * @throws EncryptionFailed
     */
    public function wrap(#[SensitiveParameter] string $sessionKey, OaepHash $hash): string
    {
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        // The digest parameter exists from PHP 8.5 only: SHA-1 passes none and keeps the default on every build.
        $digest = $hash === OaepHash::Sha1 ? [] : [$hash->openssl()];
        $wrapped = null;
        openssl_public_encrypt($sessionKey, $wrapped, $this->handle, OPENSSL_PKCS1_OAEP_PADDING, ...$digest);

        if (! is_string($wrapped)) {
            throw new EncryptionFailed('OpenSSL could not wrap the session key (section 6.2).');
        }

        return $wrapped;
    }

    /**
     * @param string $pem a block the factories wrote themselves, never the consumer's string (E-11)
     *
     * @throws InvalidKey
     */
    private static function fromPublic(string $pem): self
    {
        $handle = openssl_pkey_get_public($pem);
        // OpenSSL's error queue is left as is: nothing of the stack reads it (E-12).

        if ($handle === false) {
            throw new InvalidKey('The PEM holds no certificate and no public key (E-11).');
        }
        $details = openssl_pkey_get_details($handle);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < self::MIN_BITS) {
            throw new InvalidKey('A peer key is RSA of at least 2048 bits (E-11).');
        }

        return new self($handle);
    }
}
