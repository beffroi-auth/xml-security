<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use function array_diff;
use function array_filter;
use function array_keys;
use Beffroi\Xml\Tests\Support\Traceability;
use function count;
use function dirname;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_contains;

/**
 * The tests are the proof and the specification is the law: every invariant of section 4 of spec/enc.md, every
 * row of the hostile corpus of section 9.2 and of the behaviour corpus of section 9.3, and every CVE of the threat
 * model of section 3 is cited by at least one test of this namespace. The rows are counted in the specification
 * itself, so a row added there without a test fails here.
 */
final class TraceabilityTest extends TestCase
{
    private Traceability $traceability;

    protected function setUp(): void
    {
        $this->traceability = new Traceability(dirname(__DIR__, 3) . '/spec/enc.md', __DIR__, 'E');
    }

    /**
     * Section 4: E-1 to E-13, each cited by a test.
     */
    #[Test]
    public function everyInvariantIsCitedByATest(): void
    {
        // Given
        $invariants = $this->traceability->invariants();
        static::assertCount(13, $invariants);

        // When
        $uncited = array_diff($invariants, $this->traceability->citedInvariants());

        // Then
        static::assertSame([], $uncited, 'Invariants no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.2: every row of the hostile corpus, cited as "§9.2 row N".
     */
    #[Test]
    public function everyRowOfTheHostileCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.2 Hostile corpus');
        static::assertGreaterThan(30, count($rows));

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.2'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.2 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.3: every row of the behaviour corpus, cited as "§9.3 row N".
     */
    #[Test]
    public function everyRowOfTheBehaviourCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.3 Behaviour corpus');
        static::assertGreaterThan(15, count($rows));

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.3'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.3 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 3: every CVE of the threat model has a regression test naming it.
     */
    #[Test]
    public function everyCveOfTheThreatModelHasARegressionTest(): void
    {
        // Given
        $cves = $this->traceability->cves('## 3. Threat model', '## 4. Invariants');
        static::assertGreaterThan(1, count($cves));
        $regressions = $this->traceability->tests('/Regression');

        // When
        $uncited = array_diff(
            $cves,
            array_filter($cves, static fn (string $cve): bool => str_contains($regressions, $cve)),
        );

        // Then
        static::assertSame([], $uncited, 'CVEs of section 3 no regression test names: ' . implode(', ', $uncited));
    }
}
