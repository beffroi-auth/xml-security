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
 * The text of an element as the signer meant it (I-12, section 6.4): every text and CDATA child concatenated in
 * document order, comments and processing instructions skipped, anything else a refusal. This is the value that
 * Canonical XML without comments signs; firstChild->nodeValue and textContent are not, and are never used.
 */
final class Text
{
    /**
     * @throws MixedContent when $element has a child that is neither text, CDATA, comment nor processing instruction
     */
    public static function of(Element $element): string
    {
        $text = '';
        for ($child = $element->firstChild; $child instanceof Node; $child = $child->nextSibling) {
            // a CDATA section is a text node
            if ($child instanceof TextNode) {
                $text .= $child->data;
                continue;
            }
            if ($child instanceof Comment || $child instanceof ProcessingInstruction) {
                continue;
            }
            // an element, an entity reference: a text the brick cannot read whole is a text it does not read at all
            throw new MixedContent('The element has a child that is neither text, CDATA, comment nor processing instruction (I-12).');
        }

        return $text;
    }
}
