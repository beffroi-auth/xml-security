<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

/**
 * The two AES-CBC sizes of XML Encryption 1.1 §5.2.2, which Entra, ADFS and SimpleSAMLphp's library encrypt under
 * (section 13): read by the reading model (E-1) and opened by Decryptor::decryptCovered() only, under a verified
 * signature that covers the encrypted element (E-15). The encryptor takes a ContentAlgorithm, never one of these:
 * nothing is encrypted in CBC. aes192-cbc and 3DES are refused by name.
 */
enum CbcContentAlgorithm: string
{
    case Aes128Cbc = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    case Aes256Cbc = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    /**
     * XML Encryption 1.1 §5.2.2: the block of AES, the length of the IV before the ciphertext, the unit of the
     * ciphertext and the largest count of the padding (§5.2, E-2, E-16).
     */
    public const int BLOCK_BYTES = 16;

    /**
     * E-2: the IV and one block.
     */
    public const int MIN_CIPHER_BYTES = 2 * self::BLOCK_BYTES;

    /**
     * The length of the session key, the one length the decryptor accepts (E-2).
     *
     * @return positive-int
     */
    public function keyBytes(): int
    {
        return match ($this) {
            self::Aes128Cbc => 16,
            self::Aes256Cbc => 32,
        };
    }

    /**
     * What openssl_decrypt() takes.
     */
    public function cipher(): string
    {
        return match ($this) {
            self::Aes128Cbc => 'aes-128-cbc',
            self::Aes256Cbc => 'aes-256-cbc',
        };
    }
}
