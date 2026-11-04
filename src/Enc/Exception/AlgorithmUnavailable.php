<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * An OAEP hash other than SHA-1 on a build whose RSA functions take no digest, PHP 8.4.
 */
final class AlgorithmUnavailable extends EncryptionRefused
{
}
