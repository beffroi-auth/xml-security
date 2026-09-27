<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-1: a content encryption method outside the closed list, CBC and 3DES first among them.
 */
final class UnknownContentAlgorithm extends EncryptionRefused
{
}
