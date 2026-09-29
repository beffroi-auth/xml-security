<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc\Internal;

use function array_any;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use function count;
use Dom\Element;

/**
 * The structure of section 5.3 read strictly (E-5): direct children only, through Core's Children, counted, and
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
     * @throws MalformedEncryption
     */
    public static function refuseOtherChildren(Element $element, array $allowed, string $message): void
    {
        foreach (Children::all($element) as $child) {
            if (! array_any($allowed, static fn (Name $name): bool => $name->matches($child))) {
                throw new MalformedEncryption($message);
            }
        }
    }

    /**
     * Exactly one child named $name.
     *
     * @throws MalformedEncryption when there is none or more than one
     */
    public static function one(Element $element, Name $name, string $message): Element
    {
        $children = Children::named($element, $name);
        if (count($children) !== 1) {
            throw new MalformedEncryption($message);
        }

        return $children[0];
    }

    /**
     * At most one child named $name.
     *
     * @throws MalformedEncryption when there is more than one
     */
    public static function optional(Element $element, Name $name, string $message): ?Element
    {
        $children = Children::named($element, $name);
        if (count($children) > 1) {
            throw new MalformedEncryption($message);
        }

        return $children[0] ?? null;
    }

    /**
     * No element child at all.
     *
     * @throws MalformedEncryption
     */
    public static function none(Element $element, string $message): void
    {
        if (Children::all($element) !== []) {
            throw new MalformedEncryption($message);
        }
    }

    /**
     * The text of $element through Core's Text::of() (E-5), an element child refused under the rule of the namespace
     * rather than Core's MixedContent: nothing was decrypted, so the refusal is the model's (section 5.3).
     *
     * @throws MalformedEncryption
     */
    public static function text(Element $element, string $message): string
    {
        try {
            return Text::of($element);
        } catch (MixedContent) {
            throw new MalformedEncryption($message);
        }
    }
}
