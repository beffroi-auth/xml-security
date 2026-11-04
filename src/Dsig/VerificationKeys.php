<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use function count;
use InvalidArgumentException;
use function sprintf;

final readonly class VerificationKeys
{
    public const int MAX = 16;

    /**
     * @param list<VerificationKey> $keys one at least, sixteen at most
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public array $keys,
    ) {
        if ($keys === [] || count($keys) > self::MAX) {
            throw new InvalidArgumentException(sprintf(
                'The verification keys are one to maxVerificationKeys, %d (D-14).',
                self::MAX,
            ));
        }
    }
}
