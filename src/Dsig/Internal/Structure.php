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
 * D-9
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Structure
{
    /**
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
     * @throws MalformedSignature
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
     * @throws MalformedSignature
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
     * @throws MalformedSignature
     */
    public static function none(Element $element, string $message): void
    {
        if (Children::all($element) !== []) {
            throw new MalformedSignature($message);
        }
    }

    /**
     * An element child is refused as MalformedSignature rather than Core's MixedContent, so that the model throws
     * nothing but a SignatureRefused.
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
