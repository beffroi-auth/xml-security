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
 * The structure of section 5.3, read strictly on direct children only (E-5): nothing is searched.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Structure
{
    /**
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
     * @throws MalformedEncryption
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
     * @throws MalformedEncryption
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
     * @throws MalformedEncryption
     */
    public static function none(Element $element, string $message): void
    {
        if (Children::all($element) !== []) {
            throw new MalformedEncryption($message);
        }
    }

    /**
     * Nothing was decrypted yet, so an element child is the model's MalformedEncryption, not Core's MixedContent.
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
