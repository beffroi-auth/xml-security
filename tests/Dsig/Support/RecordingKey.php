<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Support;

use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SigningKeyInterface;

/**
 * A signing key that records what it was asked to sign and answers with what the test decided: the port of
 * section 5.2 implemented by a test, as a key management service would implement it.
 */
final class RecordingKey implements SigningKeyInterface
{
    public ?string $bytes = null;

    public ?SignatureAlgorithm $algorithm = null;

    public function __construct(
        private readonly string $answer,
    ) {
    }

    public function sign(string $bytes, SignatureAlgorithm $algorithm): string
    {
        $this->bytes = $bytes;
        $this->algorithm = $algorithm;

        return $this->answer;
    }
}
