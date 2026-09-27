<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use function defined;

/**
 * The closed list of signature methods (D-5): the RSA schemes of XML Signature 1.1 §6.4.2 and RFC 6931 §2.3,
 * PKCS#1 v1.5 and RSASSA-PSS with MGF1 and a salt of the digest's length. SHA-1, HMAC, DSA, ECDSA and every
 * unknown URI are refused by fromUri() before anything is decoded or computed. A case added is a decision of the
 * specification, never a mapping in a consumer.
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
     * @throws UnknownSignatureAlgorithm for every other URI
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownSignatureAlgorithm('The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).')
        );
    }

    /**
     * The hash of the scheme.
     */
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
     * False for a PSS scheme on a build without OPENSSL_PKCS1_PSS_PADDING, which PHP 8.5 defines and 8.4 does not
     * (specification, section 13).
     */
    public function isAvailable(): bool
    {
        return ! $this->isPss() || defined('OPENSSL_PKCS1_PSS_PADDING');
    }
}
