<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use function hash;

/**
 * The closed list of digest methods (D-5): SHA-256 of XML Signature 1.1 §6.2, SHA-384 and SHA-512 of RFC 6931
 * §2.1. SHA-1, MD5 and every unknown URI are refused by fromUri().
 */
enum DigestAlgorithm: string
{
    case Sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case Sha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case Sha512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    /**
     * @throws UnknownDigestAlgorithm for every other URI
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownDigestAlgorithm('The digest algorithm is not SHA-256, SHA-384 or SHA-512 (D-5).')
        );
    }

    /**
     * The raw digest of $bytes.
     */
    public function hash(string $bytes): string
    {
        return hash(
            match ($this) {
                self::Sha256 => 'sha256',
                self::Sha384 => 'sha384',
                self::Sha512 => 'sha512',
            },
            $bytes,
            true,
        );
    }

    /**
     * The length of a digest, in bytes.
     */
    public function length(): int
    {
        return match ($this) {
            self::Sha256 => 32,
            self::Sha384 => 48,
            self::Sha512 => 64,
        };
    }
}
