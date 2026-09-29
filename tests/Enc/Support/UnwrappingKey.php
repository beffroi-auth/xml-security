<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\OaepHash;

/**
 * A decryption key that records what it was asked to unwrap and answers with what the test decided: the port of
 * section 5.2 implemented by a test, as a key management service would implement it.
 */
final class UnwrappingKey implements DecryptionKeyInterface
{
    public ?string $wrapped = null;

    public ?OaepHash $hash = null;

    public function __construct(
        private readonly ?string $answer,
    ) {
    }

    public function unwrap(string $wrapped, OaepHash $hash): ?string
    {
        $this->wrapped = $wrapped;
        $this->hash = $hash;

        return $this->answer;
    }
}
