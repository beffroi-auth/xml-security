<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Exception;

use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: a node of a document the brick did not produce is a programming error of the caller (I-4), never
 * caught by the stack as a refusal.
 */
final class ForeignNodeTest extends TestCase
{
    #[Test]
    public function itIsALogicExceptionAndNotARefusedXml(): void
    {
        // When
        $parents = class_parents(ForeignNode::class);

        // Then
        static::assertContains(LogicException::class, $parents);
        static::assertNotContains(RefusedXml::class, $parents);
    }
}
