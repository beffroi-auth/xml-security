<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Support;

use function array_map;
use function array_unique;
use function array_values;
use function count;
use function explode;
use function file_get_contents;
use function implode;
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
 * What a traceability test reads: a specification, the invariants it declares under a prefix (I for Core, D for
 * Dsig), the rows of its corpus tables, the CVEs of its threat model, and the tests of one namespace that cite
 * them. The tests are the proof and the specification is the law: a row or an invariant added there without a
 * test is what the test built on this class fails on.
 */
final readonly class Traceability
{
    private string $specification;

    /**
     * @param string $specificationPath the absolute path of the specification
     * @param string $testsDirectory the absolute path of the tests that cite it
     * @param string $invariantPrefix "I" for the invariants I-1 to I-16 of core.md, "D" for those of dsig.md
     */
    public function __construct(
        string $specificationPath,
        private string $testsDirectory,
        private string $invariantPrefix,
    ) {
        $specification = file_get_contents($specificationPath);
        if ($specification === false) {
            throw new RuntimeException(sprintf('%s cannot be read.', $specificationPath));
        }
        $this->specification = $specification;
    }

    /**
     * The invariants section 4 declares, "I-1" to "I-16" for core.md.
     *
     * @return list<string>
     */
    public function invariants(): array
    {
        preg_match_all('~^- \*\*' . $this->invariantPrefix . '-(\d+)\.~m', $this->specification, $matches);

        return array_map(fn (string $number): string => $this->invariantPrefix . '-' . $number, $matches[1]);
    }

    /**
     * The invariants the tests cite, each once.
     *
     * @return list<string>
     */
    public function citedInvariants(): array
    {
        preg_match_all('~\b' . $this->invariantPrefix . '-(\d+)\b~', $this->tests(), $cited);

        return array_values(array_unique(
            array_map(fn (string $number): string => $this->invariantPrefix . '-' . $number, $cited[1]),
        ));
    }

    /**
     * The rows of the table under a heading, numbered from 1, the header and its separator left aside.
     *
     * @return array<int, string>
     */
    public function tableRows(string $heading): array
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
     * The rows the tests cite: "§9.2 row 6", "§9.2 rows 1 to 4", "§9.2 rows 18 and 19", "§9.2 rows 4, 6, 10 and 12".
     *
     * @return list<int>
     */
    public function citedRows(string $section): array
    {
        preg_match_all(
            '~§' . preg_quote($section, '~') . ' rows? ([0-9]+(?:(?:, | and | to )[0-9]+)*)~',
            $this->tests(),
            $matches,
        );
        $rows = [];
        foreach ($matches[1] as $citation) {
            $parts = preg_split('~, | and ~', $citation);
            if ($parts === false) {
                throw new RuntimeException(sprintf('The citation "%s" cannot be split.', $citation));
            }
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

    /**
     * The CVEs a section names, each once, sorted.
     *
     * @return list<string>
     */
    public function cves(string $from, string $until): array
    {
        preg_match_all('~CVE-\d{4}-\d+~', $this->section($from, $until), $matches);
        $cves = array_values(array_unique($matches[0]));
        sort($cves);

        return $cves;
    }

    /**
     * The source of every test under the tests directory, or under one of its subdirectories, concatenated.
     */
    public function tests(string $directory = ''): string
    {
        $sources = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $this->testsDirectory . $directory,
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

    private function section(string $from, string $until): string
    {
        $start = strpos($this->specification, $from);
        if ($start === false) {
            throw new RuntimeException(sprintf('The specification has no "%s".', $from));
        }
        $end = strpos($this->specification, $until, $start + strlen($from));

        return $end === false
            ? substr($this->specification, $start)
            : substr(
                $this->specification,
                $start,
                $end - $start,
            );
    }
}
