<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function array_diff;
use function array_filter;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use function dirname;
use function explode;
use function file_get_contents;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function preg_match_all;
use function preg_quote;
use function preg_split;
use function range;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use function sort;
use SplFileInfo;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;
use function trim;

/**
 * The tests are the proof and the specification is the law: every invariant of section 4, every row of the hostile
 * corpus of section 9.2 and of the behaviour corpus of section 9.3, and every CVE of the threat model of section 3
 * is cited by at least one test. The rows are counted in spec/core.md itself, so a row added there without a
 * test fails here.
 */
final class TraceabilityTest extends TestCase
{
    /**
     * Section 4: I-1 to I-16, each cited by a test.
     */
    #[Test]
    public function everyInvariantIsCitedByATest(): void
    {
        // Given
        preg_match_all('~^- \*\*I-(\d+)\.~m', $this->specification(), $matches);
        $invariants = array_map(static fn (string $number): string => 'I-' . $number, $matches[1]);
        static::assertCount(16, $invariants);
        preg_match_all('~\bI-(\d+)\b~', $this->tests(), $cited);

        // When
        $uncited = array_diff(
            $invariants,
            array_unique(array_map(static fn (string $number): string => 'I-' . $number, $cited[1])),
        );

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
        $rows = $this->tableRows('### 9.2 Hostile corpus');
        static::assertGreaterThan(25, count($rows));

        // When
        $uncited = array_diff(array_keys($rows), $this->citedRows('9.2'));

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
        $rows = $this->tableRows('### 9.3 Behaviour corpus');
        static::assertGreaterThan(15, count($rows));

        // When
        $uncited = array_diff(array_keys($rows), $this->citedRows('9.3'));

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
        $threatModel = $this->section('## 3. Threat model', '## 4. Invariants');
        preg_match_all('~CVE-\d{4}-\d+~', $threatModel, $matches);
        $cves = array_unique($matches[0]);
        sort($cves);
        static::assertGreaterThan(5, count($cves));
        $regressions = $this->tests('/Regression');

        // When
        $uncited = array_diff(
            $cves,
            array_unique(array_filter($cves, static fn (string $cve): bool => str_contains($regressions, $cve))),
        );

        // Then
        static::assertSame([], $uncited, 'CVEs of section 3 no regression test names: ' . implode(', ', $uncited));
    }

    /**
     * The rows of the table under a heading, numbered from 1, the header and its separator left aside.
     *
     * @return array<int, string>
     */
    private function tableRows(string $heading): array
    {
        $section = $this->section($heading, "\n### ");
        $rows = [];
        $inTable = false;
        foreach (explode("\n", $section) as $line) {
            if (! str_starts_with($line, '|')) {
                if ($inTable) {
                    break;
                }
                continue;
            }
            if (! $inTable) {
                $inTable = true;
                continue;
            }
            if (preg_match('~^\|[-| ]+\|$~', $line) === 1) {
                continue;
            }
            $rows[count($rows) + 1] = trim($line, '| ');
        }

        return $rows;
    }

    /**
     * The rows a test cites: "§9.2 row 6", "§9.2 rows 1 to 4", "§9.2 rows 18 and 19", "§9.2 rows 4, 6, 10 and 12".
     *
     * @return list<int>
     */
    private function citedRows(string $section): array
    {
        preg_match_all(
            '~§' . preg_quote($section, '~') . ' rows? ([0-9]+(?:(?:, | and | to )[0-9]+)*)~',
            $this->tests(),
            $matches,
        );
        $rows = [];
        foreach ($matches[1] as $citation) {
            $parts = preg_split('~, | and ~', $citation);
            static::assertNotFalse($parts);
            foreach ($parts as $part) {
                if (str_contains($part, ' to ')) {
                    [$from, $to] = explode(' to ', $part);
                    foreach (range((int) $from, (int) $to) as $row) {
                        $rows[] = $row;
                    }
                    continue;
                }
                $rows[] = (int) $part;
            }
        }
        sort($rows);

        return array_values(array_unique($rows));
    }

    private function section(string $from, string $until): string
    {
        $specification = $this->specification();
        $start = strpos($specification, $from);
        static::assertNotFalse($start, sprintf('The specification has no "%s".', $from));
        $end = strpos($specification, $until, $start + strlen($from));

        return $end === false ? substr($specification, $start) : substr($specification, $start, $end - $start);
    }

    private function specification(): string
    {
        $specification = file_get_contents(dirname(__DIR__, 3) . '/spec/core.md');
        if ($specification === false) {
            throw new RuntimeException('spec/core.md cannot be read.');
        }

        return $specification;
    }

    /**
     * The source of every test under tests/Core/Unit, or under one of its directories, concatenated.
     */
    private function tests(string $directory = ''): string
    {
        $sources = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            __DIR__ . $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            if ($source === false) {
                throw new RuntimeException(sprintf('%s cannot be read.', $file->getPathname()));
            }
            $sources[] = $source;
        }

        return implode("\n", $sources);
    }
}
