<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Exception;

/**
 * E-1: a key transport outside the closed list, PKCS#1 v1.5 first among them, or an RSA-OAEP whose DigestMethod and
 * MGF name different hashes.
 */
final class UnknownKeyTransport extends EncryptionRefused
{
}
