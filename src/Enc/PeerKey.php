<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use function base64_decode;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use function chunk_split;
use function is_string;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_OAEP_PADDING;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_public_encrypt;
use OpenSSLAsymmetricKey;
use function preg_replace;

/**
 * The encryption certificate of the peer's metadata (section 5.2): the certificate's PEM, the base64 of its DER as
 * an X509Certificate element carries it, or a PEM public key. RSA of at least 2048 bits (E-11). It holds an
 * OpenSSLAsymmetricKey and nothing else, and exposes neither the PEM nor the modulus; the one
 * openssl_public_encrypt() and the one openssl_pkey_get_public() of the namespace live here (E-10). Whether the
 * certificate is expired, revoked or trusted is the business of the metadata layer, which decided to pass the key.
 */
final readonly class PeerKey
{
    /**
     * Section 7, E-11: what the interoperability targets encrypt to, and the floor of the profiles.
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
     * certificate once it is wrapped in the PEM armour and refuses the bare base64 (dsig.md, section 13).
     *
     * @throws InvalidKey
     */
    public static function fromCertificateBase64(string $base64): self
    {
        $clean = preg_replace('~\s+~', '', $base64) ?? '';
        if ($clean === '' || base64_decode($clean, true) === false) {
            throw new InvalidKey('A certificate is the base64 of its DER (E-11).');
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
     * The session key wrapped under RSA-OAEP with $hash for the mask and for MGF1 (section 6.2 step 5).
     *
     * @internal for Encryptor only: the one openssl_public_encrypt() of the namespace (E-10)
     *
     * @throws AlgorithmUnavailable when this build cannot wrap under $hash
     * @throws EncryptionFailed when the primitive fails: never input
     */
    public function wrap(string $sessionKey, OaepHash $hash): string
    {
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        // the digest parameter exists on PHP 8.5 only, and isAvailable() was checked: SHA-1 leaves the default in
        // place, whatever the build (section 13)
        $digest = $hash === OaepHash::Sha1 ? [] : [$hash->openssl()];
        $wrapped = null;
        openssl_public_encrypt($sessionKey, $wrapped, $this->handle, OPENSSL_PKCS1_OAEP_PADDING, ...$digest);

        // openssl_public_encrypt() fills $wrapped or leaves it null: a key the constructor accepted never reaches the null
        if (! is_string($wrapped)) {
            throw new EncryptionFailed('OpenSSL could not wrap the session key (section 6.2).');
        }

        return $wrapped;
    }

    /**
     * @throws InvalidKey
     */
    private static function fromPublic(string $pem): self
    {
        $handle = openssl_pkey_get_public($pem);
        // openssl leaves its diagnostics in a queue whatever the outcome; nothing of the stack reads them (E-12)

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
