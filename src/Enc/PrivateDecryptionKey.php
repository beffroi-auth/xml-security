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
 * Section 5.2, E-3, E-10, E-11
 */
final readonly class PrivateDecryptionKey implements DecryptionKeyInterface
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
    public static function fromPem(
        #[SensitiveParameter]
        string $pem,
        #[SensitiveParameter]
        ?string $passphrase = null,
    ): self {
        // OpenSSL opens a file:// string as a path and prompts the terminal for a missing passphrase.
        if (str_starts_with($pem, 'file://')) {
            throw new InvalidKey('The PEM holds no private key, or the passphrase is wrong (E-11).');
        }
        $handle = openssl_pkey_get_private($pem, $passphrase ?? '');
        // OpenSSL's error queue is left as is: nothing of the stack reads it (E-12).

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
        // The digest parameter exists from PHP 8.5 only: SHA-1 passes none and keeps the default on every build.
        $digest = $hash === OaepHash::Sha1 ? [] : [$hash->openssl()];
        $sessionKey = null;
        openssl_private_decrypt($wrapped, $sessionKey, $this->handle, OPENSSL_PKCS1_OAEP_PADDING, ...$digest);
        // An OAEP error left in OpenSSL's queue would tell which step failed, so the queue is drained (E-3).
        do {
            $error = openssl_error_string();
        } while ($error !== false);

        return is_string($sessionKey) ? $sessionKey : null;
    }
}
