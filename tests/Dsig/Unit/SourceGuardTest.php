<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use function array_diff_key;
use function array_filter;
use function array_values;
use function dirname;
use function file_get_contents;
use function implode;
use function in_array;
use function is_file;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;
use function preg_match;
use function sprintf;
use function str_ends_with;
use function strlen;
use function strtolower;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_ENCAPSED_AND_WHITESPACE;
use const T_IS_EQUAL;
use const T_IS_IDENTICAL;
use const T_IS_NOT_EQUAL;
use const T_IS_NOT_IDENTICAL;
use const T_NULLSAFE_OBJECT_OPERATOR;
use const T_OBJECT_OPERATOR;
use const T_STRING;
use const T_VARIABLE;
use function trim;

/**
 * Section 8 of spec/dsig.md, read on the source of src/Dsig/ itself, next to the PHPStan rules: the tokens the
 * namespace never writes, the four OpenSSL calls confined to one file each and written once (D-15), base64
 * decoded strictly wherever it is decoded (D-8), and no digest nor signature compared with an operator.
 */
final class SourceGuardTest extends TestCase
{
    /**
     * Section 8: tokens that never appear in src/Dsig/, comments and strings left aside.
     */
    #[Test]
    #[DataProvider('provideBannedTokens')]
    public function itNeverWritesABannedToken(string $token): void
    {
        // When
        $occurrences = $this->occurrences($token);

        // Then
        static::assertSame(
            [],
            $occurrences,
            sprintf('"%s" is banned by section 8: %s', $token, implode(', ', $occurrences)),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBannedTokens(): iterable
    {
        foreach ([
            'hash_hmac(',
            'sha1(',
            'md5(',
            'openssl_private_encrypt(',
            'openssl_public_decrypt(',
            'openssl_private_decrypt(',
            'openssl_public_encrypt(',
            'openssl_x509_',
            'OPENSSL_ALGO_SHA1',
            'OPENSSL_ALGO_MD5',
            'OPENSSL_PKCS1_PADDING',
            'DOMDocument',
            'XPath',
            'textContent',
            'nodeValue',
            'file_get_contents(',
            'Reflection',
            'eval(',
            'call_user_func',
        ] as $token) {
            yield $token => [$token];
        }
    }

    /**
     * D-15: the four OpenSSL calls, one file each, written exactly once.
     */
    #[Test]
    #[DataProvider('provideConfinedCalls')]
    public function itConfinesACallToItsFile(string $token, string $file): void
    {
        // When
        $occurrences = $this->occurrences($token);

        // Then
        static::assertSame(
            [],
            array_diff_key($occurrences, [$file => true]),
            sprintf('"%s" is confined to %s (D-15).', $token, $file),
        );
        static::assertTrue(is_file($this->sourceDirectory() . '/' . $file));
        static::assertSame([$file => 1], $occurrences, sprintf('"%s" is written once, in %s (D-15).', $token, $file));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideConfinedCalls(): iterable
    {
        yield 'openssl_verify() in Verifier' => ['openssl_verify(', 'Verifier.php'];
        yield 'openssl_sign() in PrivateKey' => ['openssl_sign(', 'PrivateKey.php'];
        yield 'openssl_pkey_get_public() in VerificationKey' => ['openssl_pkey_get_public(', 'VerificationKey.php'];
        yield 'openssl_pkey_get_private() in PrivateKey' => ['openssl_pkey_get_private(', 'PrivateKey.php'];
    }

    /**
     * D-8: every base64_decode() of the namespace is strict.
     */
    #[Test]
    public function itDecodesBase64StrictlyEverywhere(): void
    {
        // When
        $lax = $this->occurrences('base64_decode(');
        $strict = $this->occurrences(', true)');

        // Then
        static::assertNotSame([], $lax);
        foreach ($lax as $file => $count) {
            static::assertGreaterThanOrEqual(
                $count,
                $strict[$file] ?? 0,
                sprintf('%s decodes base64 without the strict flag (D-8).', $file),
            );
        }
    }

    /**
     * Section 8: no digest and no signature of the namespace is compared with ==, ===, != or !==, which stop at the
     * first differing byte; hash_equals() is the comparison. A comparison with null, true, false or [] compares no
     * bytes and is left aside, and so is a value computed from the bytes, strlen() of a digest for instance.
     */
    #[Test]
    public function itComparesNoDigestAndNoSignatureWithAnOperator(): void
    {
        // When
        $comparisons = [];
        foreach ($this->files() as $file => $source) {
            foreach ($this->byteComparisons($source) as $comparison) {
                $comparisons[] = sprintf('%s: %s', $file, $comparison);
            }
        }

        // Then
        static::assertSame(
            [],
            $comparisons,
            'A digest or a signature is compared with hash_equals() only (section 8).',
        );
    }

    /**
     * The guard above finds what it looks for, and only that.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[TestWith(['<?php if ($digest === $expected) {}', ['$digest === $expected']], 'a variable on the left')]
    #[TestWith([
        '<?php return $computed == $reference->digestValue;',
        ['$computed == digestValue'],
    ], 'a property on the right')]
    #[TestWith(['<?php if ($signatureValue !== $other) {}', ['$signatureValue !== $other']], 'a signature')]
    #[TestWith(['<?php if ($a != $b->digest) {}', ['$a != digest']], 'a loose inequality')]
    #[TestWith(['<?php if ($signature === null || $digest !== false) {}', []], 'a literal')]
    #[TestWith(['<?php if (strlen($digest) !== $algorithm->length()) {}', []], 'a value computed from the bytes')]
    #[TestWith(['<?php if (hash_equals($digest, $expected) === true) {}', []], 'hash_equals()')]
    #[TestWith(['<?php if ($signed !== $element) {}', []], 'a name that is not a digest nor a signature')]
    public function itFindsTheComparisonsOfBytes(string $source, array $expected): void
    {
        // When
        $comparisons = $this->byteComparisons($source);

        // Then
        static::assertSame($expected, $comparisons);
    }

    /**
     * @return array<string, int> the files of src/Dsig/ where $token appears, with the count, comments and strings aside
     */
    private function occurrences(string $token): array
    {
        $occurrences = [];
        foreach ($this->sources() as $file => $code) {
            $count = substr_count($code, $token);
            if ($count > 0) {
                $occurrences[$file] = $count;
            }
        }

        return $occurrences;
    }

    /**
     * @return array<string, string> each source file of src/Dsig/, relative path to code with comments and strings blanked
     */
    private function sources(): array
    {
        $codes = [];
        foreach ($this->files() as $file => $source) {
            $code = '';
            foreach (PhpToken::tokenize($source) as $phpToken) {
                if (
                    $phpToken->isIgnorable() || $phpToken->is([T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE])
                ) {
                    $code .= ' ';
                    continue;
                }
                $code .= $phpToken->text;
            }
            $codes[$file] = $code;
        }

        return $codes;
    }

    /**
     * The comparisons of $source whose operand is a variable or a property named after a digest or a signature, each
     * as "left operator right", the names read from the tokens.
     *
     * @return list<string>
     */
    private function byteComparisons(string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));
        $comparisons = [];
        foreach ($tokens as $index => $token) {
            if (! $token->is([T_IS_EQUAL, T_IS_IDENTICAL, T_IS_NOT_EQUAL, T_IS_NOT_IDENTICAL])) {
                continue;
            }
            $left = $this->operandBefore($tokens, $index);
            $right = $this->operandAfter($tokens, $index);
            if ($this->isLiteral($left) || $this->isLiteral($right)) {
                continue;
            }
            if ($this->namesBytes($left) || $this->namesBytes($right)) {
                $comparisons[] = sprintf('%s %s %s', $left, $token->text, $right);
            }
        }

        return $comparisons;
    }

    /**
     * The value compared on the left of the operator at $index: a variable, the last property of a chain, a literal,
     * or "" for anything computed (a call, an expression in parentheses).
     *
     * @param list<PhpToken> $tokens
     */
    private function operandBefore(array $tokens, int $index): string
    {
        $previous = $tokens[$index - 1] ?? null;
        if ($previous === null) {
            return '';
        }
        if ($previous->is(T_VARIABLE)) {
            return $previous->text;
        }
        if ($previous->is(T_STRING)) {
            $before = $tokens[$index - 2] ?? null;
            if ($before !== null && $before->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR])) {
                return $previous->text;
            }

            return $this->isLiteral($previous->text) ? $previous->text : '';
        }

        return $previous->text === ']' && ($tokens[$index - 2] ?? null)?->text === '[' ? '[]' : '';
    }

    /**
     * The value compared on the right of the operator at $index, read as operandBefore() reads the left one.
     *
     * @param list<PhpToken> $tokens
     */
    private function operandAfter(array $tokens, int $index): string
    {
        $next = $tokens[$index + 1] ?? null;
        if ($next === null) {
            return '';
        }
        if ($next->is(T_STRING)) {
            return $this->isLiteral($next->text) ? $next->text : '';
        }
        if ($next->text === '[') {
            return ($tokens[$index + 2] ?? null)?->text === ']' ? '[]' : '';
        }
        if (! $next->is(T_VARIABLE)) {
            return '';
        }
        $name = $next->text;
        $position = $index + 2;
        while (
            ($tokens[$position] ?? null)?->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR]) === true
            && ($tokens[$position + 1] ?? null)?->is(T_STRING) === true
        ) {
            $name = $tokens[$position + 1]->text;
            $position += 2;
        }

        return ($tokens[$position] ?? null)?->text === '(' ? '' : $name;
    }

    private function isLiteral(string $operand): bool
    {
        return in_array(strtolower($operand), ['null', 'true', 'false', '[]'], true);
    }

    private function namesBytes(string $operand): bool
    {
        return preg_match('~digest|signature~i', $operand) === 1;
    }

    /**
     * @return array<string, string> each source file of src/Dsig/, relative path to its source as written
     */
    private function files(): array
    {
        $directory = $this->sourceDirectory();
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! str_ends_with($file->getFilename(), '.php')) {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            if ($source === false) {
                throw new RuntimeException(sprintf('%s cannot be read.', $file->getPathname()));
            }
            $files[trim(substr($file->getPathname(), strlen($directory)), '/')] = $source;
        }

        return $files;
    }

    private function sourceDirectory(): string
    {
        return dirname(__DIR__, 3) . '/src/Dsig';
    }
}
