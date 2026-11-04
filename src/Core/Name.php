<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Dom\Attr;
use Dom\Element;

final readonly class Name
{
    public function __construct(
        public ?string $namespace,
        public string $local,
    ) {
    }

    public static function of(Element|Attr $node): self
    {
        return new self($node->namespaceURI, $node->localName);
    }

    /**
     * I-10
     */
    public function matches(Element|Attr $node): bool
    {
        return $node->namespaceURI === $this->namespace && $node->localName === $this->local;
    }

    public function equals(self $other): bool
    {
        return $other->namespace === $this->namespace && $other->local === $this->local;
    }
}
