<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Internal;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Dom\XMLDocument;
use WeakMap;
use WeakReference;

/**
 * The documents the brick loaded or created (section 6.1 step 7): what Document::owning() reads to recognise a
 * node (I-4), and what Serializer reads to find the Dom\XMLDocument of a Document. Two weak maps, one per
 * direction. A node object does not keep the object of its document alive, so the Dom\XMLDocument is held by the
 * entry of its Document: as long as the caller holds the Document, every node of it is recognised; a Document the
 * caller drops is forgotten, and its nodes are foreign again.
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

    /**
     * The Document of a Dom\XMLDocument, if the brick produced it and the caller still holds it.
     */
    public static function owning(XMLDocument $xml): ?Document
    {
        return (self::documentMap()[$xml] ?? null)?->get();
    }

    /**
     * @throws ForeignNode when the Document was built by hand instead of by Loader or DocumentFactory
     */
    public static function xmlOf(Document $document): XMLDocument
    {
        return self::xmlMap()[$document] ?? throw new ForeignNode('The document is not one the brick produced (I-4).');
    }

    /**
     * The documents recognised: the entries whose Dom\XMLDocument is still alive.
     */
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
