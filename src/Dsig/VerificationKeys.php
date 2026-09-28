<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use function count;
use InvalidArgumentException;
use function sprintf;

/**
 * The keys of the peer's metadata, one to maxVerificationKeys (section 7, D-14): a peer carries one to three
 * signing certificates during a rotation. The verifier tries each in order and stops at the first that verifies.
 */
final readonly class VerificationKeys
{
    public const int MAX = 16;

    /**
     * @param list<VerificationKey> $keys one at least, sixteen at most
     *
     * @throws InvalidArgumentException when empty or over the bound: a programming error of the consumer, never input
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
