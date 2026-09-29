<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use function is_string;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_OAEP_PADDING;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_error_string;
use function openssl_private_decrypt;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use function str_starts_with;

/**
 * A decryption key on a PEM in memory, for the tests and for a consumer whose key is a file the deployment gives it
 * (section 5.2): RSA of at least 2048 bits (E-11). The one openssl_private_decrypt() and the one
 * openssl_pkey_get_private() of the namespace live here (E-10). It exposes nothing of the key, and answers null for
 * whatever does not unwrap, never why (E-3).
 */
final readonly class PrivateDecryptionKey implements DecryptionKeyInterface
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
     * @throws InvalidKey when the PEM holds no private key, the passphrase is wrong, or the key is not RSA of at
     *                    least 2048 bits
     */
    public static function fromPem(
        #[SensitiveParameter]
        string $pem,
        #[SensitiveParameter]
        ?string $passphrase = null,
    ): self {
        // OpenSSL opens a string that starts with file:// as a path, and asks the terminal for the passphrase of an
        // encrypted PEM given none: the key is the PEM in memory, and a missing passphrase is the empty one
        if (str_starts_with($pem, 'file://')) {
            throw new InvalidKey('The PEM holds no private key, or the passphrase is wrong (E-11).');
        }
        $handle = openssl_pkey_get_private($pem, $passphrase ?? '');
        // openssl leaves its diagnostics in a queue whatever the outcome; nothing of the stack reads them (E-12)

        if ($handle === false) {
            throw new InvalidKey('The PEM holds no private key, or the passphrase is wrong (E-11).');
        }
        $details = openssl_pkey_get_details($handle);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < self::MIN_BITS) {
            throw new InvalidKey('A decryption key is RSA of at least 2048 bits (E-11).');
        }

        return new self($handle);
    }

    public function unwrap(string $wrapped, OaepHash $hash): ?string
    {
        if (! $hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot unwrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        // the digest parameter exists on PHP 8.5 only, and isAvailable() was checked: SHA-1 leaves the default in
        // place, whatever the build (section 13)
        $digest = $hash === OaepHash::Sha1 ? [] : [$hash->openssl()];
        $sessionKey = null;
        openssl_private_decrypt($wrapped, $sessionKey, $this->handle, OPENSSL_PKCS1_OAEP_PADDING, ...$digest);
        // an OAEP decoding error left in OpenSSL's queue would tell whoever reads openssl_error_string() which step
        // failed: the queue is emptied, one error per call, whatever the outcome (section 6.1 step 4, E-3)
        do {
            $error = openssl_error_string();
        } while ($error !== false);

        // a blob that does not unwrap leaves $sessionKey null: the one answer, whatever OpenSSL knows of why (E-3)
        return is_string($sessionKey) ? $sessionKey : null;
    }
}
