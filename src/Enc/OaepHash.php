<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use function defined;

/**
 * The hash of RSA-OAEP, for the OAEP mask and for MGF1 alike (E-1): SHA-1, what rsa-oaep-mgf1p means and what
 * every interoperability target produces, and the three SHA-2 sizes XML Encryption 1.1 §5.5.2 names for rsa-oaep,
 * which PHP expresses where its RSA functions take a digest (specification, section 13). SHA-1 inside OAEP is not
 * a collision property, which is why the closed list keeps it.
 */
enum OaepHash: string
{
    case Sha1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    case Sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case Sha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case Sha512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    /**
     * @throws UnknownKeyTransport for every other URI
     */
    public static function fromDigestUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownKeyTransport('The DigestMethod of a key transport is not SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).')
        );
    }

    /**
     * The MGF URIs of XML Encryption 1.1 §5.5.2, mgf1sha1 to mgf1sha512, one per case.
     *
     * @throws UnknownKeyTransport for every other URI
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

    /**
     * The URI of XML Encryption 1.1 §5.5.2 naming MGF1 with this hash.
     */
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
     * What the digest parameter of openssl_public_encrypt() and openssl_private_decrypt() takes, on PHP 8.5.
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
     * True for SHA-1 on every build, the default of OPENSSL_PKCS1_OAEP_PADDING; for the others where the two RSA
     * functions take a digest, PHP 8.5, the release that also defined OPENSSL_PKCS1_PSS_PADDING: that constant is
     * the marker of the build, the same one Dsig reads (specification, section 13).
     */
    public function isAvailable(): bool
    {
        return $this === self::Sha1 || defined('OPENSSL_PKCS1_PSS_PADDING');
    }
}
