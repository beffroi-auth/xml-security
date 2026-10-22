<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-1: a content encryption method outside the closed lists of ContentAlgorithm and CbcContentAlgorithm, aes192-cbc, 3DES
 * and aes192-gcm first among them.
 */
final class UnknownContentAlgorithm extends EncryptionRefused
{
}
