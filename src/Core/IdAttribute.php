<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

final readonly class IdAttribute
{
    /**
     * @param ?string $elementNamespace null for any element
     */
    public function __construct(
        public Name $attribute,
        public ?string $elementNamespace = null,
    ) {
    }
}
