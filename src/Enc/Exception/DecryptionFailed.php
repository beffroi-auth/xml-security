<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-3: the one failure of decryption, whatever failed after the reading model accepted the structure: the unwrap
 * that returned nothing, a session key of the wrong length, a tag or a ciphertext the cipher refused, an empty
 * plaintext. It carries the one message and nothing else, by construction: no constructor argument can say more.
 */
final class DecryptionFailed extends EncryptionRefused
{
    public const string MESSAGE = 'The data could not be decrypted (E-3).';

    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
