<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Internal;

use function array_any;
use function array_key_exists;
use function array_pop;
use function array_push;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Exception\XmlVersionRefused;
use Beffroi\Xml\Core\IdAttribute;
use Beffroi\Xml\Core\IdAttributes;
use Beffroi\Xml\Core\Limits;
use Dom\Attr;
use Dom\CharacterData;
use Dom\DocumentType;
use Dom\Element;
use Dom\Node;
use Dom\XMLDocument;
use function preg_match;
use function sprintf;
use function str_contains;
use function strcasecmp;
use function strlen;

/**
 * The rules of section 6.1, steps 5 and 6, on a parsed document: the document checks, then one iterative pass in
 * document order over every node, bounds, namespaces and the ID index. Several of these rules are a second layer
 * behind I-1 and I-3, which stop the same input before parsing or at parsing through Loader::load(); they are
 * reached here with documents parsed outside the loader.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Inspector
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * Namespaces in XML 1.0 §3, production NCName, over the character classes of XML 1.0 fifth edition §2.3.
     */
    private const string NCNAME = '~^[A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}][A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}\-.0-9\x{B7}\x{300}-\x{36F}\x{203F}-\x{2040}]*\z~u';

    /**
     * RFC 3986 §3.1: a scheme followed by a colon.
     */
    private const string ABSOLUTE_URI = '~^[A-Za-z][A-Za-z0-9+.-]*:~';

    public function __construct(
        private IdAttributes $idAttributes,
        private Limits $limits,
    ) {
    }

    /**
     * @throws RefusedXml
     */
    public function inspect(XMLDocument $document): Document
    {
        if ($document->doctype instanceof DocumentType) {
            throw new DoctypeRefused('The document has a document type declaration (I-1).');
        }
        if ($document->xmlVersion !== '1.0') {
            throw new XmlVersionRefused('The XML version is not 1.0 (I-5).');
        }
        if (strcasecmp($document->xmlEncoding ?? 'UTF-8', 'UTF-8') !== 0) {
            throw new EncodingRefused('The declared encoding is not UTF-8 (I-5).');
        }
        $root = $document->documentElement ?? throw new MalformedXml('The document has no root element (I-3).');

        return new Document($root, $this->traverse($document));
    }

    /**
     * @return array<string, Element> the element of every registered ID value
     *
     * @throws RefusedXml
     */
    private function traverse(XMLDocument $document): array
    {
        $index = [];
        $elements = 0;
        $declarations = 0;
        $stack = self::childrenOf($document, 1);
        while ($stack !== []) {
            [$node, $depth] = array_pop($stack);
            if ($node instanceof Element) {
                if ($depth > $this->limits->maxDepth) {
                    throw new LimitExceeded(sprintf(
                        'An element is deeper than maxDepth, %d (I-7).',
                        $this->limits->maxDepth,
                    ));
                }
                if (++$elements > $this->limits->maxElements) {
                    throw new LimitExceeded(sprintf(
                        'The document has more elements than maxElements, %d (I-7).',
                        $this->limits->maxElements,
                    ));
                }
                self::refuseUnboundPrefix($node);
                $declarations = $this->inspectAttributes($node, $declarations, $index);
                array_push($stack, ...self::childrenOf($node, $depth + 1));
                continue;
            }
            // text, CDATA, comment, processing instruction: inert, the byte bound covers them
            if ($node instanceof CharacterData) {
                continue;
            }
            // an entity reference, a document type node: only a DTD produces them
            throw new DoctypeRefused(sprintf(
                'The document contains a node only a DTD can produce, of type %d (I-1).',
                $node->nodeType,
            ));
        }

        return $index;
    }

    /**
     * The children of a node, last first, so that popping the stack yields document order.
     *
     * @return list<array{Node, int}>
     */
    private static function childrenOf(Node $parent, int $depth): array
    {
        $children = [];
        for ($child = $parent->lastChild; $child instanceof Node; $child = $child->previousSibling) {
            $children[] = [$child, $depth];
        }

        return $children;
    }

    /**
     * @param array<string, Element> $index
     *
     * @throws RefusedXml
     * @return int the running count of namespace declarations
     */
    private function inspectAttributes(Element $element, int $declarations, array &$index): int
    {
        $attributes = 0;
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI === self::XMLNS) {
                if (++$declarations > $this->limits->maxNamespaceDeclarations) {
                    throw new LimitExceeded(sprintf(
                        'The document has more namespace declarations than maxNamespaceDeclarations, %d (I-7).',
                        $this->limits->maxNamespaceDeclarations,
                    ));
                }
                self::refuseRelativeNamespace($attribute);
                continue;
            }
            if (++$attributes > $this->limits->maxAttributesPerElement) {
                throw new LimitExceeded(sprintf(
                    'An element has more attributes than maxAttributesPerElement, %d (I-7).',
                    $this->limits->maxAttributesPerElement,
                ));
            }
            self::refuseUnboundPrefix($attribute);
            if ($this->isRegistered($attribute, $element)) {
                $this->index($attribute->value, $element, $index);
            }
        }

        return $declarations;
    }

    /**
     * I-6: every prefixed element or attribute has a namespace URI. The parser keeps a prefix it could not bind
     * inside the local name, after a diagnostic that I-3 refuses first (section 13).
     *
     * @throws NamespaceRefused
     */
    private static function refuseUnboundPrefix(Element|Attr $node): void
    {
        if (str_contains($node->localName, ':') || $node->prefix !== null && $node->namespaceURI === null) {
            throw new NamespaceRefused('A prefixed name has no namespace (I-6).');
        }
    }

    /**
     * I-6: an absolute URI, or the empty undeclaration of the default namespace.
     *
     * @throws NamespaceRefused
     */
    private static function refuseRelativeNamespace(Attr $declaration): void
    {
        if ($declaration->value === '' && $declaration->prefix === null) {
            return;
        }
        if (preg_match(self::ABSOLUTE_URI, $declaration->value) !== 1) {
            throw new NamespaceRefused('A namespace declaration is not an absolute URI (I-6).');
        }
    }

    /**
     * Whether the attribute is one the consumer registered, on an element it applies to (section 5.3).
     */
    private function isRegistered(Attr $attribute, Element $element): bool
    {
        return array_any(
            $this->idAttributes->attributes,
            static fn (IdAttribute $registered): bool => (
                $registered->attribute->matches($attribute)
                && ($registered->elementNamespace === null || $registered->elementNamespace === $element->namespaceURI)
            ),
        );
    }

    /**
     * I-8: an NCName no longer than the bound, seen once.
     *
     * @param array<string, Element> $index
     *
     * @throws InvalidId|DuplicateId
     */
    private function index(string $value, Element $element, array &$index): void
    {
        if (strlen($value) > $this->limits->maxIdLength) {
            throw new InvalidId(sprintf(
                'An ID is longer than maxIdLength, %d bytes (I-8).',
                $this->limits->maxIdLength,
            ));
        }
        if (preg_match(self::NCNAME, $value) !== 1) {
            throw new InvalidId('An ID is not an NCName (I-8).');
        }
        if (array_key_exists($value, $index)) {
            throw new DuplicateId('An ID value appears twice in the document (I-8).');
        }
        $index[$value] = $element;
    }
}
