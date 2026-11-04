<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\UnknownDigestAlgorithm;
use function hash;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

/**
 * D-5, XML Signature 1.1 §6.2, RFC 6931 §2.1
 */
enum DigestAlgorithm: string
{
    case Sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case Sha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case Sha512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    /**
     * @throws UnknownDigestAlgorithm
     */
    public static function fromUri(string $uri): self
    {
        return self::tryFrom($uri) ?? throw new UnknownDigestAlgorithm('The digest algorithm is not SHA-256, SHA-384 or SHA-512 (D-5).');
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

    public function opensslAlgorithm(): int
    {
        return match ($this) {
            self::Sha256 => OPENSSL_ALGO_SHA256,
            self::Sha384 => OPENSSL_ALGO_SHA384,
            self::Sha512 => OPENSSL_ALGO_SHA512,
        };
    }
}
