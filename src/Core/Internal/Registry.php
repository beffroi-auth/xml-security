<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Internal;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Dom\XMLDocument;
use WeakMap;
use WeakReference;

/**
 * The documents the brick loaded or created (I-4). A node does not keep its Dom\XMLDocument alive, so the entry of
 * its Document holds it: a Document the caller drops is forgotten, and its nodes are foreign again.
 *
 * @internal outside the compatibility promise of section 5
 */
final class Registry
{
    /**
     * @var ?WeakMap<Document, XMLDocument>
     */
    private static ?WeakMap $xmlOf = null;

    /**
     * @var ?WeakMap<XMLDocument, WeakReference<Document>>
     */
    private static ?WeakMap $documentOf = null;

    public static function register(XMLDocument $xml, Document $document): Document
    {
        self::xmlMap()[$document] = $xml;
        self::documentMap()[$xml] = WeakReference::create($document);

        return $document;
    }

    public static function owning(XMLDocument $xml): ?Document
    {
        return (self::documentMap()[$xml] ?? null)?->get();
    }

    /**
     * @throws ForeignNode
     */
    public static function xmlOf(Document $document): XMLDocument
    {
        return self::xmlMap()[$document] ?? throw new ForeignNode('The document is not one the brick produced (I-4).');
    }

    public static function count(): int
    {
        return self::documentMap()->count();
    }

    /**
     * @return WeakMap<Document, XMLDocument>
     */
    private static function xmlMap(): WeakMap
    {
        return self::$xmlOf ??= new WeakMap();
    }

    /**
     * @return WeakMap<XMLDocument, WeakReference<Document>>
     */
    private static function documentMap(): WeakMap
    {
        return self::$documentOf ??= new WeakMap();
    }
}
