<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\UnknownContentAlgorithm;

/**
 * The closed list of content encryption methods (E-1): the two AES-GCM sizes of XML Encryption 1.1 §5.2.4 the
 * stack uses. The CBC modes, 3DES, aes192-gcm and every unknown URI are refused by fromUri() before anything is
 * decoded. A case added is a decision of the specification, never a mapping in a consumer.
 */
enum ContentAlgorithm: string
{
    case Aes128Gcm = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
    case Aes256Gcm = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    /**
     * XML Encryption 1.1 §5.2.4: a 96-bit IV before the ciphertext (E-2).
     */
    public const int IV_BYTES = 12;

    /**
     * XML Encryption 1.1 §5.2.4: a 128-bit authentication tag after the ciphertext (E-2).
     */
    public const int TAG_BYTES = 16;

    /**
     * @throws UnknownContentAlgorithm for every other URI
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new UnknownContentAlgorithm('The content algorithm is not AES-128-GCM or AES-256-GCM (E-1).')
        );
    }

    /**
     * The length of the session key, the one length the decryptor accepts (E-2).
     *
     * @return positive-int
     */
    public function keyBytes(): int
    {
        return match ($this) {
            self::Aes128Gcm => 16,
            self::Aes256Gcm => 32,
        };
    }

    /**
     * What openssl_encrypt() and openssl_decrypt() take.
     */
    public function cipher(): string
    {
        return match ($this) {
            self::Aes128Gcm => 'aes-128-gcm',
            self::Aes256Gcm => 'aes-256-gcm',
        };
    }
}
