<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\SerializationFailed;
use Beffroi\Xml\Core\Internal\Registry;

/**
 * The only place of the stack that calls saveXml() (I-15): the whole document, formatOutput false, an XML
 * declaration and UTF-8, whitespace text nodes kept. Nothing reformats a serialized document afterwards: a document
 * reformatted after signing is a document whose signature no longer verifies (section 6.5).
 */
final readonly class Serializer
{
    /**
     * @throws SerializationFailed when saveXml() returns false
     * @throws ForeignNode when $document was not produced by Loader or DocumentFactory
     */
    public function serialize(Document $document): string
    {
        $xml = Registry::xmlOf($document);
        $xml->formatOutput = false;
        $bytes = $xml->saveXml();
        if ($bytes === false) {
            throw new SerializationFailed('libxml could not serialize the document (I-15).');
        }

        return $bytes;
    }
}
