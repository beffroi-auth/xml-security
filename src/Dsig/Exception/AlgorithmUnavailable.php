<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Exception;

/**
 * An RSASSA-PSS method on a build without PHP 8.5 and OpenSSL 3.1 (section 13).
 */
final class AlgorithmUnavailable extends SignatureRefused
{
}
