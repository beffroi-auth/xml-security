<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function array_pop;
use function array_push;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\SerializationFailed;
use Beffroi\Xml\Core\Internal\Registry;
use Dom\CDATASection;
use Dom\CharacterData;
use Dom\Comment;
use Dom\Element;
use Dom\Node;
use Dom\ProcessingInstruction;
use Dom\XMLDocument;
use function preg_match;
use function str_contains;
use function str_ends_with;
use function strcasecmp;

/**
 * The only place of the stack that calls saveXml() (I-15): the whole document, formatOutput false, an XML
 * declaration and UTF-8, whitespace text nodes kept. Nothing reformats a serialized document afterwards: a document
 * reformatted after signing is a document whose signature no longer verifies (section 6.5). What the serializer
 * lets out loads again as the canonical form that was signed: the four shapes that would not are refused first, and
 * so is what no parser accepts at all.
 */
final readonly class Serializer
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /** A character outside the Char production of XML 1.0 §2.2. */
    private const string NOT_A_CHAR = '/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u';

    /**
     * @throws SerializationFailed when the document holds a shape that would not survive saveXml() then a parser, or a shape no parser accepts (section 6.5), or when saveXml() returns false
     * @throws ForeignNode when $document was not produced by Loader or DocumentFactory
     */
    public function serialize(Document $document): string
    {
        $xml = Registry::xmlOf($document);
        self::refuseWhatWouldNotRoundTrip($xml);
        $xml->formatOutput = false;
        $bytes = $xml->saveXml();
        if ($bytes === false) {
            throw new SerializationFailed('libxml could not serialize the document (I-15).');
        }
        self::refuseWhatIsNotAChar($bytes);

        return $bytes;
    }

    /**
     * Section 6.5: saveXml() writes every character of a text, CDATA, comment or processing instruction node, of an
     * attribute value and of a namespace name as it is, so one pass over its output sees each of them, as step 2
     * of 6.1 does over the input.
     *
     * @throws SerializationFailed
     */
    private static function refuseWhatIsNotAChar(string $bytes): void
    {
        $found = preg_match(self::NOT_A_CHAR, $bytes);
        if ($found === false) {
            throw new SerializationFailed('The document holds bytes that are not UTF-8, which no parser accepts (section 6.5).');
        }
        if ($found === 1) {
            throw new SerializationFailed('The document holds a character outside the Char production of XML 1.0 §2.2, which no parser accepts (section 6.5).');
        }
    }

    /**
     * Section 6.5: one iterative pass in document order over every node, the comments and processing instructions
     * outside the root included, refusing the four shapes measured not to survive saveXml() then a parser and the
     * comments and processing instructions no parser accepts.
     *
     * @throws SerializationFailed
     */
    private static function refuseWhatWouldNotRoundTrip(XMLDocument $xml): void
    {
        /** @var list<array{Node, ?string}> $stack each node with the default namespace in force where it starts, as saveXml() computes it */
        $stack = self::childrenOf($xml, null);
        while ($stack !== []) {
            [$node, $inherited] = array_pop($stack);
            if ($node instanceof Element) {
                array_push($stack, ...self::childrenOf($node, self::inspectElement($node, $inherited)));
                continue;
            }
            if ($node instanceof CharacterData) {
                self::inspectCharacterData($node);
            }
        }
    }

    /**
     * The children of a node, last first, so that popping the stack yields document order.
     *
     * @return list<array{Node, ?string}>
     */
    private static function childrenOf(Node $parent, ?string $default): array
    {
        $children = [];
        for ($child = $parent->lastChild; $child instanceof Node; $child = $child->previousSibling) {
            $children[] = [$child, $default];
        }

        return $children;
    }

    /**
     * An element whose prefix is bound to the URI of the default namespace in force where it starts is written
     * without its prefix by the namespace fix-up of saveXml(), which changes its canonical form; a namespace name
     * holding an ampersand is not written faithfully.
     *
     * @throws SerializationFailed
     * @return ?string the default namespace in force for the children, as saveXml() computes it: the element's own
     *                 xmlns attribute, else its own namespace when it has no prefix, else the inherited one
     */
    private static function inspectElement(Element $element, ?string $inherited): ?string
    {
        if ($element->prefix !== null && $element->namespaceURI === $inherited) {
            throw new SerializationFailed('An element carries a prefix bound to the in-scope default namespace, which saveXml() would drop (section 6.5).');
        }
        self::refuseAmpersand($element->namespaceURI);
        $default = $element->prefix === null ? $element->namespaceURI : $inherited;
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI !== self::XMLNS) {
                self::refuseAmpersand($attribute->namespaceURI);
                continue;
            }
            self::refuseAmpersand($attribute->value);
            // xmlns itself has no prefix; xmlns:p has the prefix xmlns
            if ($attribute->prefix === null) {
                $default = $attribute->value === '' ? null : $attribute->value;
            }
        }

        return $default;
    }

    /**
     * A carriage return is written as the byte itself and normalised to a line feed by the parser of the peer
     * (XML 1.0 §2.11); a CDATA section holding the sequence that ends one, which the parser produces by merging
     * adjacent sections, is written as it is, into bytes no parser accepts; so are a comment and a processing
     * instruction their productions forbid (XML 1.0 §2.5 and §2.6).
     *
     * @throws SerializationFailed
     */
    private static function inspectCharacterData(CharacterData $node): void
    {
        if (str_contains($node->data, "\r")) {
            throw new SerializationFailed('A text, CDATA, comment or processing instruction node holds a carriage return, which a parser would normalise to a line feed (section 6.5).');
        }
        if ($node instanceof CDATASection && str_contains($node->data, ']]>')) {
            throw new SerializationFailed('A CDATA section holds the sequence that ends one, which saveXml() would write as it is (section 6.5).');
        }
        if ($node instanceof Comment && (str_contains($node->data, '--') || str_ends_with($node->data, '-'))) {
            throw new SerializationFailed('A comment holds two adjacent hyphens or ends with one, which XML 1.0 §2.5 forbids (section 6.5).');
        }
        if ($node instanceof ProcessingInstruction) {
            self::inspectProcessingInstruction($node);
        }
    }

    /**
     * @throws SerializationFailed
     */
    private static function inspectProcessingInstruction(ProcessingInstruction $node): void
    {
        if (strcasecmp($node->target, 'xml') === 0) {
            throw new SerializationFailed('A processing instruction has the target xml, which XML 1.0 §2.6 reserves (section 6.5).');
        }
        if (str_contains($node->data, '?>')) {
            throw new SerializationFailed('A processing instruction holds the sequence that ends one, which XML 1.0 §2.6 forbids (section 6.5).');
        }
    }

    /**
     * @throws SerializationFailed
     */
    private static function refuseAmpersand(?string $namespace): void
    {
        if ($namespace !== null && str_contains($namespace, '&')) {
            throw new SerializationFailed('A namespace name holds an ampersand, which saveXml() does not write faithfully (section 6.5).');
        }
    }
}
