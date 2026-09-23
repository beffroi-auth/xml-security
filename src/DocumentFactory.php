<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Internal\Registry;
use Dom\XMLDocument;

/**
 * A new document for what a consumer builds (section 6.5): XML 1.0, UTF-8, a root created with createElementNS(),
 * registered so that the brick recognises every node built under it. Consumers build with the Dom API; the brick
 * does not wrap the DOM.
 */
final readonly class DocumentFactory
{
    /**
     * A new XML 1.0, UTF-8 document whose root is $root, created with createElementNS() and the given prefix.
     */
    public function create(Name $root, ?string $prefix = null): Document
    {
        $xml = XMLDocument::createEmpty();
        $element = $xml->createElementNS(
            $root->namespace,
            $prefix === null ? $root->local : $prefix . ':' . $root->local,
        );
        $xml->appendChild($element);

        return Registry::register($xml, new Document($element, []));
    }
}
