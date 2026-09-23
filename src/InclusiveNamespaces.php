<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function preg_split;
use const PREG_SPLIT_NO_EMPTY;

/**
 * The prefixes an exclusive canonicalization renders as an inclusive one would (Exclusive XML Canonicalization
 * §4), as the PrefixList attribute of a signature carries them. Passed to libxml as they are: a prefix that names
 * no declaration in scope changes nothing (section 13).
 */
final readonly class InclusiveNamespaces
{
    /**
     * @param list<string> $prefixes each an NCName or '#default'
     */
    public function __construct(
        public array $prefixes,
    ) {
    }

    public static function none(): self
    {
        return new self([]);
    }

    /**
     * Whitespace-separated, as the PrefixList attribute carries it.
     */
    public static function fromPrefixList(string $prefixList): self
    {
        $prefixes = preg_split('~\s+~', $prefixList, -1, PREG_SPLIT_NO_EMPTY);

        return new self($prefixes === false ? [] : $prefixes);
    }
}
