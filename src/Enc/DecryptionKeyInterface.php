<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;

/**
 * The one port of the namespace (section 5.2): what unwraps the session key an EncryptedKey carries. A key
 * management service implements it without ever handing its key over, and answers null rather than a reason, so
 * that the port itself cannot become the oracle (E-3, E-6); PrivateDecryptionKey is the implementation on a PEM in
 * memory.
 */
interface DecryptionKeyInterface
{
    /**
     * The session key $wrapped carries under RSA-OAEP with $hash for the mask and for MGF1, or null when it does
     * not unwrap: never why.
     *
     * @throws AlgorithmUnavailable when this build cannot unwrap under $hash (any hash other than SHA-1 before PHP 8.5)
     */
    public function unwrap(string $wrapped, OaepHash $hash): ?string;
}
