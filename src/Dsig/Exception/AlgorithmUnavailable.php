<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * An RSASSA-PSS method on a build without OPENSSL_PKCS1_PSS_PADDING (PHP 8.4).
 */
final class AlgorithmUnavailable extends SignatureRefused
{
}
