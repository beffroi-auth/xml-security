<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use function constant;
use function is_string;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_sign;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use function str_starts_with;

/**
 * It exposes nothing of the key.
 */
final readonly class PrivateKey implements SigningKeyInterface
{
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
        // OpenSSL opens a string that starts with file:// as a path, and asks the terminal for the passphrase of an
        // encrypted PEM given none.
        if (str_starts_with($pem, 'file://')) {
            throw new InvalidKey('The PEM holds no private key, or the passphrase is wrong (D-16).');
        }
        $handle = openssl_pkey_get_private($pem, $passphrase ?? '');
        // OpenSSL leaves its diagnostics in a queue whatever the outcome; nothing of the stack reads them (D-13).

        if ($handle === false) {
            throw new InvalidKey('The PEM holds no private key, or the passphrase is wrong (D-16).');
        }
        $details = openssl_pkey_get_details($handle);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < VerificationKey::MIN_BITS) {
            throw new InvalidKey('A signing key is RSA of at least 2048 bits (D-16).');
        }

        return new self($handle);
    }

    public function sign(string $bytes, SignatureAlgorithm $algorithm): string
    {
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot produce RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');
        }
        // The padding parameter exists on PHP 8.5 only, and isAvailable() was checked (section 13).
        $padding = $algorithm->isPss() ? [constant('OPENSSL_PKCS1_PSS_PADDING')] : [];
        $signature = null;
        openssl_sign($bytes, $signature, $this->handle, $algorithm->digest()->opensslAlgorithm(), ...$padding);

        if (! is_string($signature)) {
            throw new SigningFailed('OpenSSL could not sign the canonical SignedInfo (section 6.2).');
        }

        return $signature;
    }
}
