<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use Beffroi\Xml\Enc\Exception\LimitExceeded;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Dom\Element;

/**
 * The CipherData of an EncryptedData or of an EncryptedKey (E-5): exactly one CipherValue, decoded strictly (E-7),
 * and never a CipherReference, which would send the decryptor to fetch its ciphertext somewhere else.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class CipherData
{
    /**
     * The decoded bytes of the one CipherValue.
     *
     * @throws MalformedEncryption
     * @throws LimitExceeded
     */
    public static function valueOf(Element $cipherData): string
    {
        $cipherValue = Names::xenc('CipherValue');
        Structure::refuseOtherChildren(
            $cipherData,
            [$cipherValue],
            'A CipherData holds nothing but a CipherValue, never a CipherReference (E-5).',
        );

        return Base64::decode(Structure::text(
            Structure::one($cipherData, $cipherValue, 'A CipherData holds exactly one CipherValue (E-5).'),
            'A CipherValue holds nothing but text (E-5).',
        ));
    }
}
