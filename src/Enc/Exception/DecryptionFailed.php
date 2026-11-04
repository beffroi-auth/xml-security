<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-3: the one message whatever failed, and no constructor argument that could say more.
 */
final class DecryptionFailed extends EncryptionRefused
{
    public const string MESSAGE = 'The data could not be decrypted (E-3).';

    public function __construct()
    {
        parent::__construct(self::MESSAGE);
    }
}
