<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function array_pop;
use function array_reverse;
use Beffroi\Xml\Core\Exception\CanonicalizationFailed;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Dom\Element;
use Dom\Node;
use function in_array;
use InvalidArgumentException;
use function libxml_clear_errors;
use function libxml_get_errors;
use function libxml_use_internal_errors;
use function sprintf;

/**
 * The only place of the stack that calls C14N() (I-13), in the order of section 6.3: the apex is the brick's and
 * connected, every excluded element is a strict descendant, each is detached and reinserted at its position in a
 * finally, and a false return is a refusal. The document is mutated for the duration of the call only, and is
 * identical before and after it, whether the call succeeds or fails (I-14).
 */
final readonly class Canonicalizer
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * The canonical form of $apex and its subtree, without the subtrees of $excluding.
     *
     * @param list<Element> $excluding strict descendants of $apex left out, as the enveloped signature transform leaves out ds:Signature
     *
     * @throws CanonicalizationFailed when libxml returns false or an empty string
     * @throws ForeignNode when $apex does not belong to a document of the brick
     * @throws InvalidArgumentException when $apex is not connected to its document, when an element of its subtree without a prefix has no xmlns attribute in scope declaring its namespace, when an excluded element is not a strict descendant of $apex or is listed twice, or when $inclusiveNamespaces is not empty for an inclusive method
     */
    public function canonicalize(
        Element $apex,
        CanonicalizationMethod $method,
        InclusiveNamespaces $inclusiveNamespaces = new InclusiveNamespaces([]),
        array $excluding = [],
    ): CanonicalXml {
        Document::owning($apex);
        // removal from a parent does not clear ownerDocument; PHP itself refuses to canonicalize a detached node
        if (! $apex->isConnected) {
            throw new InvalidArgumentException('The apex is not connected to its document (section 6.3).');
        }
        if ($inclusiveNamespaces->prefixes !== [] && ! $method->isExclusive()) {
            throw new InvalidArgumentException('Inclusive namespaces apply to exclusive canonicalization only (section 6.3).');
        }
        self::refuseUndeclaredDefaultNamespace($apex);
        $exclusions = $this->exclusions($apex, $excluding);

        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();
        /** @var list<array{Element, Node, ?Node}> $detached each with its parent and its next sibling */
        $detached = [];
        try {
            foreach ($exclusions as [$element, $parent]) {
                $detached[] = [$element, $parent, $element->nextSibling];
                $parent->removeChild($element);
            }
            $bytes = $apex->C14N(
                $method->isExclusive(),
                $method->withComments(),
                null,
                $inclusiveNamespaces->prefixes === [] ? null : $inclusiveNamespaces->prefixes,
            );
            if ($bytes === false) {
                throw new CanonicalizationFailed(sprintf(
                    'libxml could not canonicalize the apex: error %d (I-13).',
                    libxml_get_errors()[0]->code ?? 0,
                ));
            }

            return new CanonicalXml($bytes);
        } finally {
            foreach (array_reverse($detached) as [$element, $parent, $next]) {
                $parent->insertBefore($element, $next);
            }
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }

    /**
     * Section 6.3 step 2: every element of the apex's subtree that has no prefix is in the default namespace the
     * xmlns attributes in scope declare, the ancestors of the apex included, a child in no namespace under a default
     * namespace carrying its own xmlns="". C14N() renders the declarations that exist as attributes, or that PHP
     * materialises for a prefixed name: a default namespace given to createElementNS() without one is a namespace
     * the canonical form silently loses (measured, section 13). A loaded document always passes, the parser
     * materialises every declaration; only a built one can fail, a programming error of its builder, never input.
     *
     * @throws InvalidArgumentException
     */
    private static function refuseUndeclaredDefaultNamespace(Element $apex): void
    {
        /** @var list<array{Element, ?string}> $stack each element with the default namespace declared above it, '' for xmlns="" */
        $stack = [[$apex, self::defaultNamespaceAbove($apex)]];
        while ($stack !== []) {
            [$element, $inherited] = array_pop($stack);
            $declared = $element->getAttributeNS(self::XMLNS, 'xmlns') ?? $inherited;
            if ($element->prefix === null && $element->namespaceURI !== ($declared === '' ? null : $declared)) {
                throw new InvalidArgumentException('An element without a prefix has no xmlns attribute in scope that declares its namespace (section 6.3).');
            }
            for (
                $child = $element->lastElementChild;
                $child instanceof Element;
                $child = $child->previousElementSibling
            ) {
                $stack[] = [$child, $declared];
            }
        }
    }

    /**
     * The value of the nearest xmlns attribute on the ancestors of $element, '' for xmlns="", null when none
     * declares one.
     */
    private static function defaultNamespaceAbove(Element $element): ?string
    {
        for ($ancestor = $element->parentElement; $ancestor instanceof Element; $ancestor = $ancestor->parentElement) {
            $declared = $ancestor->getAttributeNS(self::XMLNS, 'xmlns');
            if ($declared !== null) {
                return $declared;
            }
        }

        return null;
    }

    /**
     * Every excluded element with its parent, checked before anything is detached (section 6.3 step 3).
     *
     * @param list<Element> $excluding
     *
     * @throws InvalidArgumentException
     * @return list<array{Element, Node}>
     */
    private function exclusions(Element $apex, array $excluding): array
    {
        $exclusions = [];
        $seen = [];
        foreach ($excluding as $element) {
            $parent = $element->parentNode;
            if ($parent === null || $element === $apex || ! $apex->contains($element)) {
                throw new InvalidArgumentException('An excluded element is not a strict descendant of the apex (section 6.3).');
            }
            if (in_array($element, $seen, true)) {
                throw new InvalidArgumentException('An element is excluded twice (section 6.3).');
            }
            $seen[] = $element;
            $exclusions[] = [$element, $parent];
        }

        return $exclusions;
    }
}
