<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

/**
 * An attribute whose values identify elements (section 5.3): what a consumer registers, the brick indexes.
 */
final readonly class IdAttribute
{
    /**
     * @param Name    $attribute        the attribute, for instance Name(null, 'ID')
     * @param ?string $elementNamespace the namespace URI of the elements it applies to; null for any element
     */
    public function __construct(
        public Name $attribute,
        public ?string $elementNamespace = null,
    ) {
    }
}
