<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Internal\Registry;
use Dom\XMLDocument;

/**
 * The namespace of the root is declared on it as an attribute: C14N() does not see a default namespace given to
 * createElementNS() alone (section 13).
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
