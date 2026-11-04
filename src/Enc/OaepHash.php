<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use function defined;

/**
 * XML Encryption 1.1 §5.5.2, E-1: SHA-1 stays in the closed list, OAEP not relying on the collision resistance of
 * its hash.
 */
enum OaepHash: string
{
    case Sha1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    case Sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case Sha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case Sha512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    /**
     * @throws UnknownKeyTransport
     */
    public static function fromDigestUri(string $uri): self
    {
        return self::tryFrom($uri) ?? throw new UnknownKeyTransport('The DigestMethod of a key transport is not SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).');
    }

    /**
     * @throws UnknownKeyTransport
     */
    public static function fromMgfUri(string $uri): self
    {
        foreach (self::cases() as $case) {
            if ($case->mgfUri() === $uri) {
                return $case;
            }
        }

        throw new UnknownKeyTransport('The MGF of a key transport is not MGF1 with SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).');
    }

    public function mgfUri(): string
    {
        return Names::XMLENC11 . match ($this) {
            self::Sha1 => 'mgf1sha1',
            self::Sha256 => 'mgf1sha256',
            self::Sha384 => 'mgf1sha384',
            self::Sha512 => 'mgf1sha512',
        };
    }

    /**
     * The digest parameter of openssl_public_encrypt() and openssl_private_decrypt(), on PHP 8.5.
     */
    public function openssl(): string
    {
        return match ($this) {
            self::Sha1 => 'sha1',
            self::Sha256 => 'sha256',
            self::Sha384 => 'sha384',
            self::Sha512 => 'sha512',
        };
    }

    /**
     * SHA-1 needs no digest parameter; the others need PHP 8.5, marked by OPENSSL_PKCS1_PSS_PADDING.
     */
    public function isAvailable(): bool
    {
        return $this === self::Sha1 || defined('OPENSSL_PKCS1_PSS_PADDING');
    }
}
