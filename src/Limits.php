<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use InvalidArgumentException;
use function sprintf;

/**
 * The six bounds of section 7: each a quantity a caller may raise up to its ceiling for a documented reason, never a
 * switch that removes a check (I-7).
 */
final readonly class Limits
{
    private const int MAX_BYTES_CEILING = 8_388_608;

    private const int MAX_DEPTH_CEILING = 200;

    private const int MAX_ELEMENTS_CEILING = 1_000_000;

    private const int MAX_ATTRIBUTES_PER_ELEMENT_CEILING = 1_000;

    private const int MAX_NAMESPACE_DECLARATIONS_CEILING = 10_000;

    private const int MAX_ID_LENGTH_CEILING = 1_024;

    /**
     * @throws InvalidArgumentException when a value is under 1 or over the ceiling of section 7
     */
    public function __construct(
        public int $maxBytes = 1_048_576,
        public int $maxDepth = 64,
        public int $maxElements = 10_000,
        public int $maxAttributesPerElement = 32,
        public int $maxNamespaceDeclarations = 512,
        public int $maxIdLength = 128,
    ) {
        $this->check('maxBytes', $maxBytes, self::MAX_BYTES_CEILING);
        $this->check('maxDepth', $maxDepth, self::MAX_DEPTH_CEILING);
        $this->check('maxElements', $maxElements, self::MAX_ELEMENTS_CEILING);
        $this->check('maxAttributesPerElement', $maxAttributesPerElement, self::MAX_ATTRIBUTES_PER_ELEMENT_CEILING);
        $this->check('maxNamespaceDeclarations', $maxNamespaceDeclarations, self::MAX_NAMESPACE_DECLARATIONS_CEILING);
        $this->check('maxIdLength', $maxIdLength, self::MAX_ID_LENGTH_CEILING);
    }

    private function check(string $bound, int $value, int $ceiling): void
    {
        if ($value < 1 || $value > $ceiling) {
            throw new InvalidArgumentException(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));
        }
    }
}
