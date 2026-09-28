<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\SigningFailed;

/**
 * The one port of the namespace (section 5.2): what signs the canonical bytes of a SignedInfo. A key management
 * service implements it without ever handing its key over; PrivateKey is the implementation on a PEM in memory.
 */
interface SigningKeyInterface
{
    /**
     * The signature of $bytes under $algorithm, raw.
     *
     * @throws AlgorithmUnavailable when this build cannot produce it (RSASSA-PSS without PHP 8.5 and OpenSSL 3.1)
     * @throws SigningFailed when the primitive fails
     */
    public function sign(string $bytes, SignatureAlgorithm $algorithm): string;
}
