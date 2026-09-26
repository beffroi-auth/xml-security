<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Internal\Registry;
use Dom\XMLDocument;

/**
 * The only place of the stack that calls createEmpty() (section 6.5): a new XML 1.0, UTF-8 document whose root is
 * created with createElementNS() and registered, so that the brick recognises what a consumer builds under it. The
 * namespace of the root is declared on it as an attribute: C14N() renders the declarations that exist as
 * attributes, and a default namespace given to createElementNS() alone is invisible to it (measured, section 13).
 */
final readonly class DocumentFactory
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    public function create(Name $root, ?string $prefix = null): Document
    {
        $xml = XMLDocument::createEmpty();
        $element = $xml->createElementNS(
            $root->namespace,
            $prefix === null ? $root->local : $prefix . ':' . $root->local,
        );
        if ($root->namespace !== null) {
            $element->setAttributeNS(self::XMLNS, $prefix === null ? 'xmlns' : 'xmlns:' . $prefix, $root->namespace);
        }
        $xml->appendChild($element);

        return Registry::register($xml, new Document($element, []));
    }
}
