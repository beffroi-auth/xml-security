<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use function defined;

/**
 * D-5, XML Signature 1.1 §6.4.2, RFC 6931 §2.3
 */
enum SignatureAlgorithm: string
{
    case RsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RsaSha384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RsaSha512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    case RsaPssSha256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
    case RsaPssSha384 = 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1';
    case RsaPssSha512 = 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1';

    /**
     * @throws UnknownSignatureAlgorithm
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownSignatureAlgorithm('The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).')
        );
    }

    public function digest(): DigestAlgorithm
    {
        return match ($this) {
            self::RsaSha256, self::RsaPssSha256 => DigestAlgorithm::Sha256,
            self::RsaSha384, self::RsaPssSha384 => DigestAlgorithm::Sha384,
            self::RsaSha512, self::RsaPssSha512 => DigestAlgorithm::Sha512,
        };
    }

    public function isPss(): bool
    {
        return match ($this) {
            self::RsaPssSha256, self::RsaPssSha384, self::RsaPssSha512 => true,
            self::RsaSha256, self::RsaSha384, self::RsaSha512 => false,
        };
    }

    /**
     * PSS needs PHP 8.5, which defines OPENSSL_PKCS1_PSS_PADDING, and OpenSSL 3.1, whose default salt is the
     * digest's length: PHP passes no salt length (section 13).
     */
    public function isAvailable(): bool
    {
        if (! $this->isPss()) {
            return true;
        }

        return defined('OPENSSL_PKCS1_PSS_PADDING') && OPENSSL_VERSION_NUMBER >= 0x3010_0000;
    }
}
