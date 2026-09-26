<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use function hrtime;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.5: two soft assertions, run in CI only, where the machine is known. The measured baseline is 13 ms for
 * the document at the six default bounds on the development machine (section 13).
 */
#[RequiresEnvironmentVariable('CI')]
final class PerformanceTest extends TestCase
{
    /**
     * Section 9.5: loading and indexing the largest fixture of section 9.4 takes less than 50 ms.
     */
    #[Test]
    public function itLoadsTheLargestRealDocumentInLessThan50Milliseconds(): void
    {
        // Given
        $bytes = Fixtures::bytes('real/entra-common-federation-metadata-2026-09-23.xml');

        // When
        $start = hrtime(true);
        $document = Loaded::document($bytes);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertTrue($document->hasId('_2cac9ed1-b223-4fb8-83bd-03d6f59d682d'));
        static::assertLessThan(50, $milliseconds);
    }

    /**
     * Section 9.5: loading a synthetic document at the six default bounds takes less than 500 ms.
     */
    #[Test]
    public function itLoadsADocumentAtTheSixDefaultBoundsInLessThan500Milliseconds(): void
    {
        // Given
        $bytes = Fixtures::bytes('behaviour/at-the-six-default-bounds-loads.xml');

        // When
        $start = hrtime(true);
        $document = Loaded::document($bytes);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertSame('Response', $document->root()->localName);
        static::assertLessThan(500, $milliseconds);
    }
}
