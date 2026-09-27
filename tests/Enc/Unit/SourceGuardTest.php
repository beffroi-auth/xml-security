<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use function array_diff_key;
use function dirname;
use function file_get_contents;
use function implode;
use function is_file;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;
use function sprintf;
use function str_ends_with;
use function strlen;
use function substr;
use function substr_count;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_ENCAPSED_AND_WHITESPACE;
use function trim;

/**
 * Section 8 of spec/enc.md, read on the source of src/Enc/ itself, next to the PHPStan rules: the tokens the
 * namespace never writes, the four OpenSSL calls and the two key readers confined to one file each and written once
 * (E-10), and base64 decoded strictly wherever it is decoded (E-7).
 */
final class SourceGuardTest extends TestCase
{
    /**
     * Section 8: tokens that never appear in src/Enc/, comments and strings left aside.
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
            'cbc',
            'hash_hmac(',
            'sha1(',
            'md5(',
            'openssl_private_encrypt(',
            'openssl_public_decrypt(',
            'openssl_sign(',
            'openssl_verify(',
            'openssl_cipher_iv_length(',
            'openssl_cipher_key_length(',
            'openssl_random_pseudo_bytes(',
            'openssl_x509_',
            'OPENSSL_PKCS1_PADDING',
            'OPENSSL_NO_PADDING',
            'OPENSSL_ZERO_PADDING',
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
     * E-10: the four OpenSSL calls and the two key readers, one file each, written exactly once.
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
            sprintf('"%s" is confined to %s (E-10).', $token, $file),
        );
        static::assertTrue(is_file($this->sourceDirectory() . '/' . $file));
        static::assertSame([$file => 1], $occurrences, sprintf('"%s" is written once, in %s (E-10).', $token, $file));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideConfinedCalls(): iterable
    {
        yield 'openssl_decrypt() in Decryptor' => ['openssl_decrypt(', 'Decryptor.php'];
        yield 'openssl_encrypt() in Encryptor' => ['openssl_encrypt(', 'Encryptor.php'];
        yield 'openssl_private_decrypt() in PrivateDecryptionKey' => [
            'openssl_private_decrypt(',
            'PrivateDecryptionKey.php',
        ];
        yield 'openssl_public_encrypt() in PeerKey' => ['openssl_public_encrypt(', 'PeerKey.php'];
        yield 'openssl_pkey_get_public() in PeerKey' => ['openssl_pkey_get_public(', 'PeerKey.php'];
        yield 'openssl_pkey_get_private() in PrivateDecryptionKey' => [
            'openssl_pkey_get_private(',
            'PrivateDecryptionKey.php',
        ];
    }

    /**
     * E-7: every base64_decode() of the namespace is strict.
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
                sprintf('%s decodes base64 without the strict flag (E-7).', $file),
            );
        }
    }

    /**
     * @return array<string, int> the files of src/Enc/ where $token appears, with the count, comments and strings aside
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
     * @return array<string, string> each source file of src/Enc/, relative path to code with comments and strings blanked
     */
    private function sources(): array
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
            $files[trim(substr($file->getPathname(), strlen($directory)), '/')] = $code;
        }

        return $files;
    }

    private function sourceDirectory(): string
    {
        return dirname(__DIR__, 3) . '/src/Enc';
    }
}
