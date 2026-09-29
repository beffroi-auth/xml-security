<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Libxml;
use Beffroi\Xml\Tests\Core\Support\Stack;
use function ini_get;
use function libxml_use_internal_errors;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SensitiveParameterValue;
use function str_repeat;

/**
 * Section 6.1, in order, against the hostile corpus of section 9.2: each fixture loaded with the SAML stack's
 * IdAttributes and the default Limits, each asserting the named exception and, where libxml gives one, the line.
 */
final class LoaderTest extends TestCase
{
    private Loader $loader;

    protected function setUp(): void
    {
        $this->loader = new Loader(Stack::idAttributes());
    }

    /**
     * Section 6.1 step 7: a Document holding the root and the index, recognised by owning().
     */
    /**
     * Section 5: the bytes are a SensitiveParameter, so that the trace of a refusal never carries them, a decrypted
     * plaintext among them.
     */
    #[Test]
    public function itKeepsTheBytesItRefusesOutOfTheTrace(): void
    {
        // Given
        if (ini_get('zend.exception_ignore_args') === '1') {
            static::markTestSkipped('This build leaves the arguments out of every trace.');
        }
        $loader = new Loader(Stack::idAttributes());

        // When
        try {
            $loader->load('<!DOCTYPE a><a>a plaintext</a>');
            static::fail('A DOCTYPE is refused.');
        } catch (DoctypeRefused $refused) {
            // Then
            static::assertInstanceOf(SensitiveParameterValue::class, $refused->getTrace()[0]['args'][0] ?? null);
            static::assertStringNotContainsString('a plaintext', $refused->getTraceAsString());
        }
    }

    #[Test]
    public function itLoadsADocumentAndIndexesItsIds(): void
    {
        // When
        $document = $this->loader->load(Fixtures::bytes('behaviour/response-with-assertion.xml'));

        // Then
        static::assertSame('Response', $document->root()->localName);
        static::assertSame('_response', $document->root()->getAttributeNS(null, 'ID'));
        static::assertSame('Assertion', $document->elementById('_assertion')->localName);
        static::assertSame($document, Document::owning($document->root()));
    }

    /**
     * Section 7, §9.5: a document at the six default bounds at once loads; every bound is a strict comparison.
     */
    #[Test]
    public function itLoadsADocumentAtTheSixDefaultBounds(): void
    {
        // When
        $document = $this->loader->load(Fixtures::bytes('behaviour/at-the-six-default-bounds-loads.xml'));

        // Then
        static::assertTrue($document->hasId('_' . str_repeat('a', 127)));
    }

    /**
     * I-15, section 6.1: whitespace-only text nodes, CDATA sections and comments are kept exactly as parsed.
     */
    #[Test]
    public function itKeepsWhitespaceCdataAndComments(): void
    {
        // When
        $root = $this->loader->load('<a> <b/> <![CDATA[x]]><!--c--><?pi d?></a>')->root();

        // Then
        static::assertSame(6, $root->childNodes->length);
    }

    /**
     * I-5, section 12: a UTF-8 byte order mark is accepted, Entra's federation metadata starts with one.
     */
    #[Test]
    public function itAcceptsAUtf8ByteOrderMark(): void
    {
        // When
        $root = $this->loader->load("\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"utf-8\"?><a/>")->root();

        // Then
        static::assertSame('a', $root->localName);
    }

    /**
     * §9.2 row 5, I-2: an xi:include element is an ordinary element without the flag; nothing is included.
     */
    #[Test]
    public function itLoadsAnXincludeElementWithoutIncludingAnything(): void
    {
        // When
        $root = $this->loader->load(Fixtures::bytes('hostile/xinclude-element-loads.xml'))->root();

        // Then
        $include = $root->firstElementChild;
        static::assertNotNull($include);
        static::assertSame('include', $include->localName);
        static::assertSame('http://www.w3.org/2001/XInclude', $include->namespaceURI);
        static::assertFalse($include->hasChildNodes());
        static::assertSame(1, $root->childNodes->length);
    }

    /**
     * §9.2 row 24, I-8: a letter is an NCName start character.
     */
    #[Test]
    public function itAcceptsALetterAsAnIdStartCharacter(): void
    {
        // When
        $document = $this->loader->load(Fixtures::bytes('hostile/id-letter-e-acute-loads.xml'));

        // Then
        static::assertTrue($document->hasId('é'));
    }

    /**
     * §9.2 row 25, section 5.3: unregistered attributes are not IDs, duplicated or not.
     */
    #[Test]
    public function itIgnoresAnIdAttributeInAnUnregisteredNamespace(): void
    {
        // When
        $document = $this->loader->load(Fixtures::bytes('hostile/id-unregistered-namespace-duplicate-loads.xml'));

        // Then
        static::assertFalse($document->hasId('x'));
    }

    /**
     * §9.2 rows 1 to 4, I-1: a DOCTYPE, wherever it sits, a comment or a CDATA section included, the entities it
     * declares never read.
     */
    #[Test]
    #[DataProvider('provideDoctypes')]
    public function itRefusesADoctypeBeforeParsing(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDoctypes(): iterable
    {
        yield 'internal entity referenced in content' => ['hostile/doctype-internal-entity-refused.xml'];
        yield 'external entity, file' => ['hostile/doctype-external-entity-file-refused.xml'];
        yield 'external entity, http' => ['hostile/doctype-external-entity-http-refused.xml'];
        yield 'parameter entity' => ['hostile/doctype-parameter-entity-refused.xml'];
        yield 'external DTD subset' => ['hostile/doctype-external-subset-refused.xml'];
        yield 'billion laughs' => ['hostile/doctype-billion-laughs-refused.xml'];
        yield 'inside a comment, the accepted false positive' => ['hostile/doctype-in-comment-refused.xml'];
        yield 'inside a CDATA section, the accepted false positive' => ['hostile/doctype-in-cdata-refused.xml'];
    }

    /**
     * Section 9.1, I-1: the originals of Canonical XML 1.0 §3 that carry a document type declaration.
     */
    #[Test]
    #[DataProvider('provideOriginalVectorsWithADoctype')]
    public function itRefusesTheOriginalVectorsThatCarryADoctype(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOriginalVectorsWithADoctype(): iterable
    {
        yield '§3.1 PIs, comments and outside of document element' => ['hostile/c14n-3.1-original-doctype-refused.xml'];
        yield '§3.3 start and end tags' => ['hostile/c14n-3.3-original-doctype-refused.xml'];
        yield '§3.4 character modifications and character references' => [
            'hostile/c14n-3.4-original-doctype-refused.xml',
        ];
        yield '§3.5 entity references, refused by design' => ['hostile/c14n-3.5-original-doctype-refused.xml'];
        yield '§3.7 document subsets, refused by design' => ['hostile/c14n-3.7-original-doctype-refused.xml'];
    }

    /**
     * Section 9.1, I-5: the original of Canonical XML 1.0 §3.6 declares ISO-8859-1.
     */
    #[Test]
    public function itRefusesTheOriginalVectorThatDeclaresIso88591(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/c14n-3.6-original-iso-8859-1-refused.xml');

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The declared encoding is not UTF-8 (I-5).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 6, I-7: one byte over maxBytes, before anything else reads the input.
     */
    #[Test]
    public function itRefusesOneByteOverMaxBytes(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/bytes-one-over-max-bytes-refused.xml');

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The input is larger than maxBytes, 1048576 bytes (I-7).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 7, I-7: the root is at depth 1, an element at depth 65 is over the default.
     */
    #[Test]
    public function itRefusesDepth65(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/depth-65-refused.xml');

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('An element is deeper than maxDepth, 64 (I-7).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 8, section 7: libxml refuses depth 256 during parsing, before the traversal runs.
     */
    #[Test]
    public function itRefusesDepth300AsMalformed(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/depth-300-malformed-refused.xml');

        // Then
        $this->expectException(MalformedXml::class);
        $this->expectExceptionMessageIs('libxml refused the input: error 1, level 3, at line 1, column 772 (I-3).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 9, I-7 and I-8: one over each of the other bounds, the bound named.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideOneOverABound')]
    public function itRefusesOneOverABound(string $fixture, string $exception, string $message): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideOneOverABound(): iterable
    {
        yield 'maxElements' => [
            'hostile/elements-10001-refused.xml',
            LimitExceeded::class,
            'The document has more elements than maxElements, 10000 (I-7).',
        ];
        yield 'maxAttributesPerElement' => [
            'hostile/attributes-33-refused.xml',
            LimitExceeded::class,
            'An element has more attributes than maxAttributesPerElement, 32 (I-7).',
        ];
        yield 'maxNamespaceDeclarations' => [
            'hostile/namespace-declarations-513-refused.xml',
            LimitExceeded::class,
            'The document has more namespace declarations than maxNamespaceDeclarations, 512 (I-7).',
        ];
        yield 'maxIdLength' => [
            'hostile/id-129-bytes-refused.xml',
            InvalidId::class,
            'An ID is longer than maxIdLength, 128 bytes (I-8).',
        ];
    }

    /**
     * §9.2 row 10, I-5: a UTF-16 or UTF-32 byte order mark, before parsing; libxml would accept UTF-16 and report
     * UTF-8 (section 13).
     */
    #[Test]
    #[DataProvider('provideByteOrderMarks')]
    public function itRefusesAUtf16OrUtf32ByteOrderMark(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The input starts with a UTF-16 or UTF-32 byte order mark (I-5).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideByteOrderMarks(): iterable
    {
        yield 'UTF-16LE' => ['hostile/bom-utf16le-refused.xml'];
        yield 'UTF-16BE' => ['hostile/bom-utf16be-refused.xml'];
        yield 'UTF-32LE' => ['hostile/bom-utf32le-refused.xml'];
        yield 'UTF-32BE' => ['hostile/bom-utf32be-refused.xml'];
    }

    /**
     * §9.2 row 11, I-5: libxml converts and parses a declared ISO-8859-1; the declaration is read after parsing.
     */
    #[Test]
    public function itRefusesADeclaredEncodingOtherThanUtf8(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/declared-iso-8859-1-refused.xml');

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The declared encoding is not UTF-8 (I-5).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 12, I-3: a declared UTF-16 over UTF-8 bytes, a mismatch libxml refuses itself (code 81).
     */
    #[Test]
    public function itRefusesADeclaredUtf16OverUtf8BytesAsMalformed(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/declared-utf-16-over-utf-8-refused.xml');

        // Then
        $this->expectException(MalformedXml::class);
        $this->expectExceptionMessageIs('libxml refused the input: error 81, level 3, at line 1, column 38 (I-3).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 13, I-5: bytes that are not UTF-8, before parsing.
     */
    #[Test]
    #[DataProvider('provideInvalidUtf8')]
    public function itRefusesBytesThatAreNotUtf8(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The input is not valid UTF-8 (I-5).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidUtf8(): iterable
    {
        yield 'overlong sequence C0 AF' => ['hostile/utf8-overlong-refused.xml'];
        yield 'lone continuation byte' => ['hostile/utf8-lone-continuation-refused.xml'];
    }

    /**
     * §9.2 row 14, I-3: XML 1.1 parses with a level-1 warning, and a warning is a refusal.
     */
    #[Test]
    public function itRefusesXml11AsADiagnostic(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/xml-version-1-1-refused.xml');

        // Then
        $this->expectException(ParserDiagnostic::class);
        $this->expectExceptionMessageIs('libxml reported a diagnostic: error 97, level 1, at line 1, column 20 (I-3).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 rows 15 to 17, I-3: an unbound prefix, an empty prefixed namespace, a rebound xml prefix and a reused
     * xmlns namespace parse with a level-2 diagnostic, and a diagnostic is a refusal.
     */
    #[Test]
    #[DataProvider('provideNamespaceDiagnostics')]
    public function itRefusesANamespaceDiagnostic(string $fixture, string $message): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(ParserDiagnostic::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNamespaceDiagnostics(): iterable
    {
        yield 'unbound prefix on an element' => [
            'hostile/unbound-prefix-element-refused.xml',
            'libxml reported a diagnostic: error 201, level 2, at line 1, column 7 (I-3).',
        ];
        yield 'unbound prefix on an attribute' => [
            'hostile/unbound-prefix-attribute-refused.xml',
            'libxml reported a diagnostic: error 201, level 2, at line 1, column 13 (I-3).',
        ];
        yield 'xmlns:x=""' => [
            'hostile/xmlns-prefix-empty-refused.xml',
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 16 (I-3).',
        ];
        yield 'xmlns:xml="urn:wrong"' => [
            'hostile/xmlns-xml-rebound-refused.xml',
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 27 (I-3).',
        ];
        yield 'a prefix bound to the xmlns namespace name' => [
            'hostile/xmlns-namespace-reused-refused.xml',
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 45 (I-3).',
        ];
    }

    /**
     * §9.2 row 18, I-6: a relative namespace URI, which libxml parses without a diagnostic.
     */
    #[Test]
    public function itRefusesARelativeNamespaceUri(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/namespace-relative-refused.xml');

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A namespace declaration is not an absolute URI (I-6).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 rows 19 and 20, I-3, I-16: malformed input, with libxml's code, line and column and never its message.
     */
    #[Test]
    #[DataProvider('provideMalformedInputs')]
    public function itRefusesMalformedInputWithLineAndColumn(string $fixture, string $message): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(MalformedXml::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedInputs(): iterable
    {
        yield 'duplicate attribute' => [
            'hostile/attribute-duplicate-refused.xml',
            'libxml refused the input: error 42, level 3, at line 1, column 17 (I-3).',
        ];
        yield 'unclosed tag' => [
            'hostile/tag-unclosed-refused.xml',
            'libxml refused the input: error 76, level 3, at line 1, column 15 (I-3).',
        ];
        yield 'NUL byte' => [
            'hostile/nul-byte-refused.xml',
            'libxml refused the input: error 77, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'control character' => [
            'hostile/control-character-refused.xml',
            'libxml refused the input: error 9, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'U+FFFE' => [
            'hostile/u-fffe-refused.xml',
            'libxml refused the input: error 9, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'undefined entity reference without DOCTYPE' => [
            'hostile/entity-undefined-refused.xml',
            'libxml refused the input: error 26, level 3, at line 1, column 12 (I-3).',
        ];
    }

    /**
     * §9.2 row 21, I-8: two saml:Assertion elements with the same ID refuse the whole document.
     */
    #[Test]
    public function itRefusesTwoAssertionsWithTheSameId(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/id-duplicate-assertion-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 22, I-8, section 6.2: one ID space over every registered attribute at once.
     */
    #[Test]
    public function itRefusesAnAssertionIdEqualToASignatureId(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/id-duplicate-across-attributes-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);
        $this->expectExceptionMessageIs('An ID value appears twice in the document (I-8).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * §9.2 row 23, I-8: an ID that is not an NCName (Namespaces in XML 1.0 §3).
     */
    #[Test]
    #[DataProvider('provideInvalidIds')]
    public function itRefusesAnIdThatIsNotAnNcname(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException(InvalidId::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (I-8).');

        // When
        $this->loader->load($bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidIds(): iterable
    {
        yield 'starts with a digit' => ['hostile/id-starts-with-digit-refused.xml'];
        yield 'holds a colon' => ['hostile/id-with-colon-refused.xml'];
        yield 'empty' => ['hostile/id-empty-refused.xml'];
        yield 'leading space' => ['hostile/id-leading-space-refused.xml'];
    }

    /**
     * Section 6.1 step 4: an empty input is refused before the parser is called, which would throw a ValueError.
     */
    #[Test]
    public function itRefusesAnEmptyInput(): void
    {
        // Then
        $this->expectException(MalformedXml::class);
        $this->expectExceptionMessageIs('The input is empty (I-3).');

        // When
        $this->loader->load('');
    }

    /**
     * I-3: the internal-errors mode is restored after a load, on the success path.
     */
    #[Test]
    public function itRestoresAnInternalErrorsModeOfFalseAfterALoad(): void
    {
        // Given
        libxml_use_internal_errors(false);

        // When
        $this->loader->load('<a/>');

        // Then
        static::assertFalse(Libxml::mode());
    }

    /**
     * I-3: the internal-errors mode is restored after a refusal, on the exception path.
     */
    #[Test]
    public function itRestoresAnInternalErrorsModeOfFalseAfterARefusal(): void
    {
        // Given
        libxml_use_internal_errors(false);

        // When
        try {
            $this->loader->load('<a>');
        } catch (MalformedXml) {
        }

        // Then
        static::assertFalse(Libxml::mode());
    }

    /**
     * I-3, section 6.1 step 4: a full buffer is emptied by a load and the mode is kept; a host that reads the
     * buffer reads it before calling the loader.
     */
    #[Test]
    public function itEmptiesAFullBufferOnALoad(): void
    {
        // Given
        Libxml::fillBuffer();

        // When
        $this->loader->load('<a/>');

        // Then
        static::assertSame([], Libxml::buffer());
        static::assertTrue(Libxml::mode());
    }

    /**
     * I-3: the buffer is emptied after a refusal too; the diagnostic that refused is not left behind.
     */
    #[Test]
    public function itEmptiesTheBufferAfterARefusal(): void
    {
        // Given
        Libxml::fillBuffer();

        // When
        try {
            $this->loader->load('<a>');
        } catch (MalformedXml) {
        }

        // Then
        static::assertSame([], Libxml::buffer());
        static::assertTrue(Libxml::mode());
    }

    /**
     * §9.2 rows 4, 6, 10 and 13, section 6.1 steps 1 to 3: the size, the bytes and the DOCTYPE are checked before
     * parsing, which the untouched buffer of libxml shows.
     */
    #[Test]
    #[DataProvider('provideRefusalsBeforeParsing')]
    public function itRefusesBeforeParsing(string $fixture): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);
        Libxml::fillBuffer();

        // When
        try {
            $this->loader->load($bytes);
        } catch (RefusedXml) {
        }

        // Then
        static::assertCount(1, Libxml::buffer());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusalsBeforeParsing(): iterable
    {
        yield 'one byte over maxBytes' => ['hostile/bytes-one-over-max-bytes-refused.xml'];
        yield 'a UTF-16 byte order mark' => ['hostile/bom-utf16le-refused.xml'];
        yield 'bytes that are not UTF-8' => ['hostile/utf8-overlong-refused.xml'];
        yield 'a DOCTYPE' => ['hostile/doctype-billion-laughs-refused.xml'];
    }
}
