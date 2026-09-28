<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig\Internal;

use function array_any;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use function count;
use Dom\Element;

/**
 * The structure of section 5.3 read strictly (D-9): direct children only, through Core's Children, counted, and
 * every child that is not one of the names allowed refused. Nothing is searched.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Structure
{
    /**
     * Every element child of $element is one of $allowed.
     *
     * @param list<Name> $allowed
     *
     * @throws MalformedSignature
     */
    public static function refuseOtherChildren(Element $element, array $allowed, string $message): void
    {
        foreach (Children::all($element) as $child) {
            if (! array_any($allowed, static fn (Name $name): bool => $name->matches($child))) {
                throw new MalformedSignature($message);
            }
        }
    }

    /**
     * Exactly one child named $name.
     *
     * @throws MalformedSignature when there is none or more than one
     */
    public static function one(Element $element, Name $name, string $message): Element
    {
        $children = Children::named($element, $name);
        if (count($children) !== 1) {
            throw new MalformedSignature($message);
        }

        return $children[0];
    }

    /**
     * At most one child named $name.
     *
     * @throws MalformedSignature when there is more than one
     */
    public static function optional(Element $element, Name $name, string $message): ?Element
    {
        $children = Children::named($element, $name);
        if (count($children) > 1) {
            throw new MalformedSignature($message);
        }

        return $children[0] ?? null;
    }

    /**
     * No element child at all.
     *
     * @throws MalformedSignature
     */
    public static function none(Element $element, string $message): void
    {
        if (Children::all($element) !== []) {
            throw new MalformedSignature($message);
        }
    }

    /**
     * The text of $element through Core's Text::of() (D-9), an element child refused under the rule of the namespace
     * rather than Core's MixedContent, so that the model throws nothing but a SignatureRefused.
     *
     * @throws MalformedSignature
     */
    public static function text(Element $element, string $message): string
    {
        try {
            return Text::of($element);
        } catch (MixedContent) {
            throw new MalformedSignature($message);
        }
    }
}
