<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function array_key_exists;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Core\Internal\Registry;
use Dom\Element;
use Dom\Node;
use Dom\XMLDocument;

final readonly class Document
{
    /**
     * @internal constructed by Loader and DocumentFactory only
     *
     * @param array<string, Element> $index keyed by ID value
     */
    public function __construct(
        private Element $root,
        private array $index,
    ) {
    }

    public function root(): Element
    {
        return $this->root;
    }

    /**
     * The index built at load, compared exactly: never getElementById(), never xml:id, never a search (I-9).
     *
     * @throws UnknownId
     */
    public function elementById(string $id): Element
    {
        return $this->index[$id] ?? throw new UnknownId('No element carries that ID (section 6.2).');
    }

    public function hasId(string $id): bool
    {
        return array_key_exists($id, $this->index);
    }

    /**
     * @throws ForeignNode
     */
    public static function owning(Node $node): self
    {
        $xml = $node instanceof XMLDocument ? $node : $node->ownerDocument;
        if (! $xml instanceof XMLDocument) {
            throw new ForeignNode('The node belongs to a document the brick did not produce (I-4).');
        }

        return Registry::owning($xml) ?? throw new ForeignNode('The node belongs to a document the brick did not produce (I-4).');
    }
}
