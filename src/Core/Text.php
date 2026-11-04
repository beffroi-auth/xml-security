<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\MixedContent;
use Dom\Comment;
use Dom\Element;
use Dom\Node;
use Dom\ProcessingInstruction;
use Dom\Text as TextNode;

/**
 * The value Canonical XML without comments signs; firstChild->nodeValue and textContent are not, and are never
 * used (I-12).
 */
final class Text
{
    /**
     * @throws MixedContent
     */
    public static function of(Element $element): string
    {
        $text = '';
        for ($child = $element->firstChild; $child instanceof Node; $child = $child->nextSibling) {
            // A CDATA section is a text node.
            if ($child instanceof TextNode) {
                $text .= $child->data;
                continue;
            }
            if ($child instanceof Comment || $child instanceof ProcessingInstruction) {
                continue;
            }
            throw new MixedContent('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');
        }

        return $text;
    }
}
