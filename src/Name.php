<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Dom\Attr;
use Dom\Element;

/**
 * The name of an element or an attribute: a namespace URI and a local name, never a prefix (I-10).
 */
final readonly class Name
{
    /**
     * @param ?string $namespace null when the node is in no namespace (an unprefixed attribute, an element under xmlns="")
     */
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
     * The namespace URI and the local name of the node, never its prefix.
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
