<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-2, E-5, E-7: the structure, a Type, a base64 text or a length is not what section 5.3 of the specification says.
 */
final class MalformedEncryption extends EncryptionRefused
{
}
