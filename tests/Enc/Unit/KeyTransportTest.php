<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Throwable;

/**
 * Section 5.1 and 6.1 step 2, E-1: RSA-OAEP with one hash, read from the EncryptionMethod of an EncryptedKey;
 * PKCS#1 v1.5, key wrapping, key agreement and an rsa-oaep whose hashes differ refused by name.
 */
final class KeyTransportTest extends TestCase
{
    private const string SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    private const string SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    private const string SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';

    private const string SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    /**
     * Section 5.1: SHA-1 for the mask and for MGF1, what every interoperability target produces and accepts.
     */
    #[Test]
    public function itsMgf1pIsSha1(): void
    {
        // When
        $transport = KeyTransport::mgf1p();

        // Then
        static::assertSame(OaepHash::Sha1, $transport->hash);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', $transport->uri());
    }

    /**
     * §9.3 row 13: rsa-oaep-mgf1p for SHA-1, rsa-oaep otherwise.
     */
    #[Test]
    public function itWritesTheUriOfItsHash(): void
    {
        // When / Then
        static::assertSame(KeyTransport::RSA_OAEP_MGF1P, new KeyTransport(OaepHash::Sha1)->uri());
        static::assertSame(KeyTransport::RSA_OAEP, new KeyTransport(OaepHash::Sha256)->uri());
        static::assertSame(KeyTransport::RSA_OAEP, new KeyTransport(OaepHash::Sha384)->uri());
        static::assertSame(KeyTransport::RSA_OAEP, new KeyTransport(OaepHash::Sha512)->uri());
    }

    /**
     * Section 6.1 step 2, E-1: every EncryptionMethod the namespace reads, with the hash it names; §9.1 row 4 the
     * DigestMethod of SHA-1 Shibboleth and ADFS write under rsa-oaep-mgf1p, §9.1 row 5 the rsa-oaep of SHA-256.
     */
    #[Test]
    #[DataProvider('provideAcceptedMethods')]
    public function itReadsAnEncryptionMethodOfTheClosedList(string $algorithm, string $children, OaepHash $hash): void
    {
        // Given
        $document = $this->method($algorithm, $children);

        // When
        $transport = KeyTransport::of($document->root());

        // Then
        static::assertSame($hash, $transport->hash);
    }

    /**
     * @return iterable<string, array{string, string, OaepHash}>
     */
    public static function provideAcceptedMethods(): iterable
    {
        yield 'rsa-oaep-mgf1p without child' => [KeyTransport::RSA_OAEP_MGF1P, '', OaepHash::Sha1];
        yield 'rsa-oaep-mgf1p with the DigestMethod of SHA-1' => [
            KeyTransport::RSA_OAEP_MGF1P,
            self::digest(self::SHA1),
            OaepHash::Sha1,
        ];
        yield 'rsa-oaep-mgf1p with a comment and whitespace' => [
            KeyTransport::RSA_OAEP_MGF1P,
            "\n  <!-- nothing -->\n  " . self::digest(self::SHA1) . "\n",
            OaepHash::Sha1,
        ];
        yield 'rsa-oaep without child, SHA-1 by default' => [KeyTransport::RSA_OAEP, '', OaepHash::Sha1];
        yield 'rsa-oaep with a DigestMethod of SHA-1 only' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA1),
            OaepHash::Sha1,
        ];
        yield 'rsa-oaep with an MGF of SHA-1 only' => [KeyTransport::RSA_OAEP, self::mgf('sha1'), OaepHash::Sha1];
        yield 'rsa-oaep naming SHA-1 twice' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA1) . self::mgf('sha1'),
            OaepHash::Sha1,
        ];
        yield 'rsa-oaep naming SHA-256 twice' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA256) . self::mgf('sha256'),
            OaepHash::Sha256,
        ];
        yield 'rsa-oaep naming SHA-256 twice, the MGF first' => [
            KeyTransport::RSA_OAEP,
            self::mgf('sha256') . self::digest(self::SHA256),
            OaepHash::Sha256,
        ];
        yield 'rsa-oaep naming SHA-384 twice' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA384) . self::mgf('sha384'),
            OaepHash::Sha384,
        ];
        yield 'rsa-oaep naming SHA-512 twice' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA512) . self::mgf('sha512'),
            OaepHash::Sha512,
        ];
    }

    /**
     * §9.2 rows 3 to 9, E-1, E-5: every EncryptionMethod the namespace refuses, with the rule named and never the
     * input (E-12).
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedMethods')]
    public function itRefusesAnEncryptionMethod(
        ?string $algorithm,
        string $children,
        string $exception,
        string $message,
    ): void {
        // Given
        $document = $this->method($algorithm, $children);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        KeyTransport::of($document->root());
    }

    /**
     * @return iterable<string, array{?string, string, class-string<Throwable>, string}>
     */
    public static function provideRefusedMethods(): iterable
    {
        $notOaep = 'The key transport is not RSA-OAEP: PKCS#1 v1.5, key wrapping and key agreement are refused by name (E-1).';
        $differ = 'The DigestMethod and the MGF of rsa-oaep name different hashes, which PHP cannot express (E-1).';
        $mgf1pDigest = 'The DigestMethod of rsa-oaep-mgf1p names a hash other than SHA-1, the one MGF1 uses under that name (E-1).';
        $mgf1pChild = 'An EncryptionMethod of rsa-oaep-mgf1p holds nothing but a DigestMethod (E-5).';
        $oaepChild = 'An EncryptionMethod of rsa-oaep holds nothing but a DigestMethod and an MGF (E-5).';
        $digestUnknown = 'The DigestMethod of a key transport is not SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).';
        $mgfUnknown = 'The MGF of a key transport is not MGF1 with SHA-1, SHA-256, SHA-384 or SHA-512 (E-1).';
        $names = 'A DigestMethod or an MGF names its Algorithm (E-5).';
        $noChild = 'A DigestMethod or an MGF holds no child (E-5).';
        $oneDigest = 'An EncryptionMethod holds at most one DigestMethod (E-5).';
        $oaepParams = '<xenc:OAEPparams>AAAA</xenc:OAEPparams>';

        yield 'row 3, rsa-1_5' => [Names::XMLENC . 'rsa-1_5', '', UnknownKeyTransport::class, $notOaep];
        yield 'row 3, rsa-1_5 next to a valid content method changes nothing' => [
            Names::XMLENC . 'rsa-1_5',
            self::digest(self::SHA1),
            UnknownKeyTransport::class,
            $notOaep,
        ];
        yield 'row 4, kw-aes256' => [Names::XMLENC . 'kw-aes256', '', UnknownKeyTransport::class, $notOaep];
        yield 'row 4, kw-aes128' => [Names::XMLENC . 'kw-aes128', '', UnknownKeyTransport::class, $notOaep];
        yield 'ECDH-ES' => [Names::XMLENC11 . 'ECDH-ES', '', UnknownKeyTransport::class, $notOaep];
        yield 'a content method as the key transport' => [
            Names::XMLENC11 . 'aes256-gcm',
            '',
            UnknownKeyTransport::class,
            $notOaep,
        ];
        yield 'a case that differs' => [Names::XMLENC . 'RSA-OAEP-MGF1P', '', UnknownKeyTransport::class, $notOaep];
        yield 'a trailing character' => [KeyTransport::RSA_OAEP_MGF1P . '/', '', UnknownKeyTransport::class, $notOaep];
        yield 'empty' => ['', '', UnknownKeyTransport::class, $notOaep];
        yield 'no Algorithm' => [
            null,
            '',
            MalformedEncryption::class,
            'An EncryptionMethod names its Algorithm (E-5).',
        ];
        yield 'row 5, rsa-oaep with a DigestMethod of SHA-256 and an MGF of SHA-1' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA256) . self::mgf('sha1'),
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'row 6, rsa-oaep with a DigestMethod of SHA-256 and no MGF' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA256),
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'rsa-oaep with an MGF of SHA-256 and no DigestMethod' => [
            KeyTransport::RSA_OAEP,
            self::mgf('sha256'),
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'rsa-oaep with a DigestMethod of SHA-1 and an MGF of SHA-512' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA1) . self::mgf('sha512'),
            UnknownKeyTransport::class,
            $differ,
        ];
        yield 'row 7, rsa-oaep-mgf1p with a DigestMethod of SHA-256' => [
            KeyTransport::RSA_OAEP_MGF1P,
            self::digest(self::SHA256),
            UnknownKeyTransport::class,
            $mgf1pDigest,
        ];
        yield 'row 8, rsa-oaep-mgf1p with an MGF' => [
            KeyTransport::RSA_OAEP_MGF1P,
            self::mgf('sha1'),
            MalformedEncryption::class,
            $mgf1pChild,
        ];
        yield 'row 9, rsa-oaep-mgf1p with an OAEPparams' => [
            KeyTransport::RSA_OAEP_MGF1P,
            $oaepParams,
            MalformedEncryption::class,
            $mgf1pChild,
        ];
        yield 'rsa-oaep with an OAEPparams' => [
            KeyTransport::RSA_OAEP,
            $oaepParams,
            MalformedEncryption::class,
            $oaepChild,
        ];
        yield 'rsa-oaep with a KeySize' => [
            KeyTransport::RSA_OAEP,
            '<xenc:KeySize>2048</xenc:KeySize>',
            MalformedEncryption::class,
            $oaepChild,
        ];
        yield 'rsa-oaep with a DigestMethod of MD5' => [
            KeyTransport::RSA_OAEP,
            self::digest('http://www.w3.org/2001/04/xmldsig-more#md5'),
            UnknownKeyTransport::class,
            $digestUnknown,
        ];
        yield 'rsa-oaep-mgf1p with a DigestMethod of MD5' => [
            KeyTransport::RSA_OAEP_MGF1P,
            self::digest('http://www.w3.org/2001/04/xmldsig-more#md5'),
            UnknownKeyTransport::class,
            $digestUnknown,
        ];
        yield 'rsa-oaep with an MGF outside the list' => [
            KeyTransport::RSA_OAEP,
            self::mgf('md5'),
            UnknownKeyTransport::class,
            $mgfUnknown,
        ];
        yield 'rsa-oaep with two DigestMethods' => [
            KeyTransport::RSA_OAEP,
            self::digest(self::SHA1) . self::digest(self::SHA1),
            MalformedEncryption::class,
            $oneDigest,
        ];
        yield 'rsa-oaep-mgf1p with two DigestMethods' => [
            KeyTransport::RSA_OAEP_MGF1P,
            self::digest(self::SHA1) . self::digest(self::SHA1),
            MalformedEncryption::class,
            $oneDigest,
        ];
        yield 'rsa-oaep with two MGFs' => [
            KeyTransport::RSA_OAEP,
            self::mgf('sha1') . self::mgf('sha1'),
            MalformedEncryption::class,
            'An EncryptionMethod holds at most one MGF (E-5).',
        ];
        yield 'a DigestMethod without Algorithm' => [
            KeyTransport::RSA_OAEP,
            '<ds:DigestMethod/>',
            MalformedEncryption::class,
            $names,
        ];
        yield 'a DigestMethod without Algorithm under rsa-oaep-mgf1p' => [
            KeyTransport::RSA_OAEP_MGF1P,
            '<ds:DigestMethod/>',
            MalformedEncryption::class,
            $names,
        ];
        yield 'an MGF without Algorithm' => [
            KeyTransport::RSA_OAEP,
            '<xenc11:MGF/>',
            MalformedEncryption::class,
            $names,
        ];
        yield 'a DigestMethod with a child' => [
            KeyTransport::RSA_OAEP,
            '<ds:DigestMethod Algorithm="' . self::SHA1 . '"><ds:Foo/></ds:DigestMethod>',
            MalformedEncryption::class,
            $noChild,
        ];
        yield 'an MGF with a child' => [
            KeyTransport::RSA_OAEP,
            '<xenc11:MGF Algorithm="' . Names::XMLENC11 . 'mgf1sha1"><xenc11:Foo/></xenc11:MGF>',
            MalformedEncryption::class,
            $noChild,
        ];
    }

    /**
     * §9.2 row 35, Core I-4: an EncryptionMethod of a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesAnElementOfAForeignDocument(): void
    {
        // Given
        $root = Foreign::parse('<xenc:EncryptionMethod xmlns:xenc="'
        . Names::XMLENC
        . '" Algorithm="'
        . KeyTransport::RSA_OAEP_MGF1P
        . '"/>')->documentElement;
        static::assertNotNull($root);

        // Then
        $this->expectException(ForeignNode::class);

        // When
        KeyTransport::of($root);
    }

    /**
     * §9.2 row 35, E-5: an element of another name, whatever it holds.
     */
    #[Test]
    public function itRefusesAnElementThatIsNotAnEncryptionMethod(): void
    {
        // Given
        $document = Loaded::document('<foo:Anything xmlns:foo="urn:foo" Algorithm="'
        . KeyTransport::RSA_OAEP_MGF1P
        . '"/>');

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The element is not an xenc:EncryptionMethod (E-5).');

        // When
        KeyTransport::of($document->root());
    }

    /**
     * An EncryptionMethod of an EncryptedKey, alone in a document, with the three namespaces its children use.
     */
    private function method(?string $algorithm, string $children): Document
    {
        return Loaded::document(sprintf(
            '<xenc:EncryptionMethod xmlns:xenc="%s" xmlns:ds="%s" xmlns:xenc11="%s"%s>%s</xenc:EncryptionMethod>',
            Names::XMLENC,
            Names::DSIG,
            Names::XMLENC11,
            $algorithm === null ? '' : ' Algorithm="' . $algorithm . '"',
            $children,
        ));
    }

    private static function digest(string $uri): string
    {
        return '<ds:DigestMethod Algorithm="' . $uri . '"/>';
    }

    private static function mgf(string $hash): string
    {
        return '<xenc11:MGF Algorithm="' . Names::XMLENC11 . 'mgf1' . $hash . '"/>';
    }
}
