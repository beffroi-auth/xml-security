<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

/**
 * XML Encryption 1.1 §5.2.2
 *
 * Read because Entra, ADFS and SimpleSAMLphp's library encrypt under it (section 13); opened only under a
 * signature that covers the encrypted element (E-15), and never used to encrypt.
 */
enum CbcContentAlgorithm: string
{
    case Aes128Cbc = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    case Aes256Cbc = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    /**
     * XML Encryption 1.1 §5.2.2
     */
    public const int BLOCK_BYTES = 16;

    /**
     * E-2: the IV and one block.
     */
    public const int MIN_CIPHER_BYTES = 2 * self::BLOCK_BYTES;

    /**
     * @return positive-int
     */
    public function keyBytes(): int
    {
        return match ($this) {
            self::Aes128Cbc => 16,
            self::Aes256Cbc => 32,
        };
    }

    public function cipher(): string
    {
        return match ($this) {
            self::Aes128Cbc => 'aes-128-cbc',
            self::Aes256Cbc => 'aes-256-cbc',
        };
    }
}
