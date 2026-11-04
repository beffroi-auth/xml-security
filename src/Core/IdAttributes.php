<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

/**
 * The values of the registered attributes form one space per document (I-8).
 */
final readonly class IdAttributes
{
    /**
     * @param list<IdAttribute> $attributes
     */
    public function __construct(
        public array $attributes,
    ) {
    }

    public static function none(): self
    {
        return new self([]);
    }

    public function withAttribute(IdAttribute $attribute): self
    {
        return new self([...$this->attributes, $attribute]);
    }
}
