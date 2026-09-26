<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use function array_filter;
use function array_values;
use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\MissingChild;
use function count;
use Dom\Element;
use function sprintf;

/**
 * Direct-child navigation, and nothing that searches descendants (I-11, section 6.4): an element wrapped inside
 * another is not a child of the root and is never found by a consumer that navigates from it, which is what a
 * signature wrapping relies on. Names match on namespace URI and local name (I-10).
 */
final class Children
{
    /**
     * @return list<Element> the element children of $parent, in document order
     */
    public static function all(Element $parent): array
    {
        $children = [];
        for ($child = $parent->firstElementChild; $child instanceof Element; $child = $child->nextElementSibling) {
            $children[] = $child;
        }

        return $children;
    }

    /**
     * @return list<Element>
     */
    public static function named(Element $parent, Name $name): array
    {
        return array_values(array_filter(self::all($parent), $name->matches(...)));
    }

    /**
     * @throws MissingChild when $parent has no child of that name
     * @throws AmbiguousChild when it has two or more
     */
    public static function one(Element $parent, Name $name): Element
    {
        $children = self::named($parent, $name);

        return match (count($children)) {
            0 => throw new MissingChild(sprintf(
                'The element has no child named %s (section 6.4).',
                self::describe($name),
            )),
            1 => $children[0],
            default => throw new AmbiguousChild(sprintf(
                'The element has more than one child named %s (section 6.4).',
                self::describe($name),
            )),
        };
    }

    /**
     * @throws AmbiguousChild when $parent has two or more children of that name
     */
    public static function optional(Element $parent, Name $name): ?Element
    {
        $children = self::named($parent, $name);
        if (count($children) > 1) {
            throw new AmbiguousChild(sprintf(
                'The element has more than one child named %s (section 6.4).',
                self::describe($name),
            ));
        }

        return $children[0] ?? null;
    }

    /**
     * The name a consumer asked for, never the input: in Clark notation when it has a namespace.
     */
    private static function describe(Name $name): string
    {
        return $name->namespace === null ? $name->local : sprintf('{%s}%s', $name->namespace, $name->local);
    }
}
