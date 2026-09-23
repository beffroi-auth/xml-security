<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core\Tests\Unit;

use function array_map;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Tests\Support\Fixtures;
use Beffroi\Xml\Core\Tests\Support\Foreign;
use Beffroi\Xml\Core\Tests\Support\Loaded;
use Beffroi\Xml\Core\Tests\Support\Nodes;
use Beffroi\Xml\Core\Tests\Support\Stack;
use DOMException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;

/**
 * The adversarial pass: for each row of section 3, inputs section 9 does not list, written to defeat the invariant.
 * DOCTYPE placement and casing, encoding and byte order mark variants, overlong and surrogate sequences, ID values
 * that would collide after a normalisation the brick must not do, prefix rebinding and xmlns games, documents at and
 * just over every bound, comments and processing instructions at every position, detached and foreign nodes. Every
 * attempt is a fixture whatever its outcome (adversarial-*-refused.xml, adversarial-*-loads.xml); none bypassed a
 * rule. I-1, I-2, I-3, I-4, I-5, I-6, I-7, I-8, I-10, I-11, I-12, I-13, I-14.
 */
final class AdversarialTest extends TestCase
{
    /**
     * Section 3: an attempt the brick refuses, with the rule named.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedAttempts')]
    public function itRefusesAnAttemptWithTheRuleNamed(string $fixture, string $exception, string $message): void
    {
        // Given
        $bytes = Fixtures::bytes($fixture);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        Loaded::document($bytes);
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideRefusedAttempts(): iterable
    {
        yield 'attribute with raw less than' => [
            'hostile/adversarial-attribute-with-raw-less-than-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 38, level 3, at line 1, column 9 (I-3).',
        ];
        yield 'attribute without quotes' => [
            'hostile/adversarial-attribute-without-quotes-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 39, level 3, at line 1, column 8 (I-3).',
        ];
        yield 'attributes 33 with one namespaced' => [
            'hostile/adversarial-attributes-33-with-one-namespaced-refused.xml',
            LimitExceeded::class,
            'An element has more attributes than maxAttributesPerElement, 32 (I-7).',
        ];
        yield 'bom utf8 after the declaration' => [
            'hostile/adversarial-bom-utf8-after-the-declaration-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 4, level 3, at line 1, column 22 (I-3).',
        ];
        yield 'bom utf8 twice' => [
            'hostile/adversarial-bom-utf8-twice-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 4, level 3, at line 1, column 1 (I-3).',
        ];
        yield 'cdata end marker in text' => [
            'hostile/adversarial-cdata-end-marker-in-text-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 62, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'character reference control' => [
            'hostile/adversarial-character-reference-control-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 11 (I-3).',
        ];
        yield 'character reference nul' => [
            'hostile/adversarial-character-reference-nul-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 10 (I-3).',
        ];
        yield 'character reference surrogate' => [
            'hostile/adversarial-character-reference-surrogate-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 14 (I-3).',
        ];
        yield 'comment before the declaration' => [
            'hostile/adversarial-comment-before-the-declaration-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 64, level 3, at line 1, column 14 (I-3).',
        ];
        yield 'comment marker inside attribute value' => [
            'hostile/adversarial-comment-marker-inside-attribute-value-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 38, level 3, at line 1, column 9 (I-3).',
        ];
        yield 'comment nested' => [
            'hostile/adversarial-comment-nested-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 80, level 3, at line 1, column 15 (I-3).',
        ];
        yield 'comment with double hyphen' => [
            'hostile/adversarial-comment-with-double-hyphen-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 80, level 3, at line 1, column 13 (I-3).',
        ];
        yield 'declaration encoding before version' => [
            'hostile/adversarial-declaration-encoding-before-version-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 96, level 3, at line 1, column 7 (I-3).',
        ];
        yield 'declaration only' => [
            'hostile/adversarial-declaration-only-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 4, level 3, at line 2, column 1 (I-3).',
        ];
        yield 'declaration version 1.2' => [
            'hostile/adversarial-declaration-version-1.2-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 97, level 1, at line 1, column 20 (I-3).',
        ];
        yield 'declaration version 10' => [
            'hostile/adversarial-declaration-version-10-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 34, level 3, at line 1, column 17 (I-3).',
        ];
        yield 'declared encoding latin1 alias' => [
            'hostile/adversarial-declared-encoding-latin1-alias-refused.xml',
            EncodingRefused::class,
            'The declared encoding is not UTF-8 (I-5).',
        ];
        yield 'declared encoding us ascii' => [
            'hostile/adversarial-declared-encoding-us-ascii-refused.xml',
            EncodingRefused::class,
            'The declared encoding is not UTF-8 (I-5).',
        ];
        yield 'declared encoding utf 8 with trailing space' => [
            'hostile/adversarial-declared-encoding-utf-8-with-trailing-space-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 34, level 3, at line 1, column 36 (I-3).',
        ];
        yield 'declared encoding utf8 without hyphen' => [
            'hostile/adversarial-declared-encoding-utf8-without-hyphen-refused.xml',
            EncodingRefused::class,
            'The declared encoding is not UTF-8 (I-5).',
        ];
        yield 'doctype after bom' => [
            'hostile/adversarial-doctype-after-bom-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype after declaration external' => [
            'hostile/adversarial-doctype-after-declaration-external-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype after root' => [
            'hostile/adversarial-doctype-after-root-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype inside a processing instruction' => [
            'hostile/adversarial-doctype-inside-a-processing-instruction-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype inside an attribute value' => [
            'hostile/adversarial-doctype-inside-an-attribute-value-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype internal subset with only a comment' => [
            'hostile/adversarial-doctype-internal-subset-with-only-a-comment-refused.xml',
            DoctypeRefused::class,
            'The input contains a document type declaration (I-1).',
        ];
        yield 'doctype lowercase' => [
            'hostile/adversarial-doctype-lowercase-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 68, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'doctype mixed case' => [
            'hostile/adversarial-doctype-mixed-case-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 68, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'doctype split by a comment' => [
            'hostile/adversarial-doctype-split-by-a-comment-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 68, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'element name starting with digit' => [
            'hostile/adversarial-element-name-starting-with-digit-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 68, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'empty after bom' => [
            'hostile/adversarial-empty-after-bom-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 4, level 3, at line 1, column 1 (I-3).',
        ];
        yield 'entity reference in attribute without doctype' => [
            'hostile/adversarial-entity-reference-in-attribute-without-doctype-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 26, level 3, at line 1, column 14 (I-3).',
        ];
        yield 'form feed in text' => [
            'hostile/adversarial-form-feed-in-text-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'id 130 bytes of two byte characters' => [
            'hostile/adversarial-id-130-bytes-of-two-byte-characters-refused.xml',
            InvalidId::class,
            'An ID is longer than maxIdLength, 128 bytes (I-8).',
        ];
        yield 'id character reference trailing space' => [
            'hostile/adversarial-id-character-reference-trailing-space-refused.xml',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'id shared between protocol and metadata namespaces' => [
            'hostile/adversarial-id-shared-between-protocol-and-metadata-namespaces-refused.xml',
            DuplicateId::class,
            'An ID value appears twice in the document (I-8).',
        ];
        yield 'id starts with combining mark' => [
            'hostile/adversarial-id-starts-with-combining-mark-refused.xml',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'id tab inside' => [
            'hostile/adversarial-id-tab-inside-refused.xml',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'id trailing space' => [
            'hostile/adversarial-id-trailing-space-refused.xml',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'id xml id duplicated is not registered' => [
            'hostile/adversarial-id-xml-id-duplicated-is-not-registered-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 513, level 2, at line 1, column 34 (I-3).',
        ];
        yield 'many namespace declarations 513 one per element' => [
            'hostile/adversarial-many-namespace-declarations-513-one-per-element-refused.xml',
            LimitExceeded::class,
            'The document has more namespace declarations than maxNamespaceDeclarations, 512 (I-7).',
        ];
        yield 'nul in attribute' => [
            'hostile/adversarial-nul-in-attribute-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 9 (I-3).',
        ];
        yield 'pi named XML uppercase' => [
            'hostile/adversarial-pi-named-XML-uppercase-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 64, level 3, at line 1, column 11 (I-3).',
        ];
        yield 'pi named xml inside root' => [
            'hostile/adversarial-pi-named-xml-inside-root-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 64, level 3, at line 1, column 11 (I-3).',
        ];
        yield 'tag name with colon only' => [
            'hostile/adversarial-tag-name-with-colon-only-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 202, level 2, at line 1, column 6 (I-3).',
        ];
        yield 'tag with leading space' => [
            'hostile/adversarial-tag-with-leading-space-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 68, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'text after the root' => [
            'hostile/adversarial-text-after-the-root-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 5, level 3, at line 1, column 7 (I-3).',
        ];
        yield 'two root elements' => [
            'hostile/adversarial-two-root-elements-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 5, level 3, at line 1, column 7 (I-3).',
        ];
        yield 'u ffff in text' => [
            'hostile/adversarial-u-ffff-in-text-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 6 (I-3).',
        ];
        yield 'utf16le without bom' => [
            'hostile/adversarial-utf16le-without-bom-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 9, level 3, at line 1, column 2 (I-3).',
        ];
        yield 'utf8 above u10ffff' => [
            'hostile/adversarial-utf8-above-u10ffff-refused.xml',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
        yield 'utf8 encoded surrogate' => [
            'hostile/adversarial-utf8-encoded-surrogate-refused.xml',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
        yield 'utf8 overlong four bytes' => [
            'hostile/adversarial-utf8-overlong-four-bytes-refused.xml',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
        yield 'utf8 overlong three bytes' => [
            'hostile/adversarial-utf8-overlong-three-bytes-refused.xml',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
        yield 'utf8 truncated sequence' => [
            'hostile/adversarial-utf8-truncated-sequence-refused.xml',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
        yield 'whitespace before the declaration' => [
            'hostile/adversarial-whitespace-before-the-declaration-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 64, level 3, at line 1, column 7 (I-3).',
        ];
        yield 'xml space invalid value' => [
            'hostile/adversarial-xml-space-invalid-value-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 102, level 1, at line 1, column 24 (I-3).',
        ];
        yield 'xmlns default bound to the xml namespace' => [
            'hostile/adversarial-xmlns-default-bound-to-the-xml-namespace-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 50 (I-3).',
        ];
        yield 'xmlns default bound to the xmlns namespace' => [
            'hostile/adversarial-xmlns-default-bound-to-the-xmlns-namespace-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 43 (I-3).',
        ];
        yield 'xmlns default relative on a child' => [
            'hostile/adversarial-xmlns-default-relative-on-a-child-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 100, level 1, at line 1, column 25 (I-3).',
        ];
        yield 'xmlns prefix declared twice on one element' => [
            'hostile/adversarial-xmlns-prefix-declared-twice-on-one-element-refused.xml',
            MalformedXml::class,
            'libxml refused the input: error 42, level 3, at line 1, column 37 (I-3).',
        ];
        yield 'xmlns prefix named xmlns' => [
            'hostile/adversarial-xmlns-prefix-named-xmlns-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 200, level 2, at line 1, column 25 (I-3).',
        ];
        yield 'xmlns prefix rebound relative on a child' => [
            'hostile/adversarial-xmlns-prefix-rebound-relative-on-a-child-refused.xml',
            NamespaceRefused::class,
            'A namespace declaration is not an absolute URI (I-6).',
        ];
        yield 'xmlns two prefixes one uri duplicate attribute' => [
            'hostile/adversarial-xmlns-two-prefixes-one-uri-duplicate-attribute-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 203, level 2, at line 1, column 53 (I-3).',
        ];
        yield 'xmlns uri with a line feed reference' => [
            'hostile/adversarial-xmlns-uri-with-a-line-feed-reference-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 99, level 2, at line 1, column 27 (I-3).',
        ];
        yield 'xmlns uri with a space' => [
            'hostile/adversarial-xmlns-uri-with-a-space-refused.xml',
            ParserDiagnostic::class,
            'libxml reported a diagnostic: error 99, level 2, at line 1, column 23 (I-3).',
        ];
    }

    /**
     * Section 3, section 8: an attempt the brick accepts on purpose, consistently with what the specification
     * accepts, and loads as an ordinary document.
     */
    #[Test]
    #[DataProvider('provideAcceptedAttempts')]
    public function itLoadsAnAttemptTheSpecificationAccepts(string $fixture): void
    {
        // When
        $document = Loaded::fixture($fixture);

        // Then
        static::assertTrue($document->root()->isConnected);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedAttempts(): iterable
    {
        yield 'attribute value with line feed' => ['behaviour/adversarial-attribute-value-with-line-feed-loads.xml'];
        yield 'attribute value with tab reference' => [
            'behaviour/adversarial-attribute-value-with-tab-reference-loads.xml',
        ];
        yield 'attribute xmlns like local name in another namespace' => [
            'behaviour/adversarial-attribute-xmlns-like-local-name-in-another-namespace-loads.xml',
        ];
        yield 'attributes 32 plus 512 declarations on one element' => [
            'behaviour/adversarial-attributes-32-plus-512-declarations-on-one-element-loads.xml',
        ];
        yield 'bytes exactly at max with a bom' => ['behaviour/adversarial-bytes-exactly-at-max-with-a-bom-loads.xml'];
        yield 'cdata nested marker' => ['behaviour/adversarial-cdata-nested-marker-loads.xml'];
        yield 'character reference tab and max' => ['behaviour/adversarial-character-reference-tab-and-max-loads.xml'];
        yield 'comment and pi before and after root' => [
            'behaviour/adversarial-comment-and-pi-before-and-after-root-loads.xml',
        ];
        yield 'comment marker inside text' => ['behaviour/adversarial-comment-marker-inside-text-loads.xml'];
        yield 'cr lf line endings' => ['behaviour/adversarial-cr-lf-line-endings-loads.xml'];
        yield 'cr only line endings' => ['behaviour/adversarial-cr-only-line-endings-loads.xml'];
        yield 'declaration version 1.0 with spaces' => [
            'behaviour/adversarial-declaration-version-1.0-with-spaces-loads.xml',
        ];
        yield 'deeply nested at the bound with siblings' => [
            'behaviour/adversarial-deeply-nested-at-the-bound-with-siblings-loads.xml',
        ];
        yield 'element name with unicode' => ['behaviour/adversarial-element-name-with-unicode-loads.xml'];
        yield 'element named xml' => ['behaviour/adversarial-element-named-xml-loads.xml'];
        yield 'element named xmlns' => ['behaviour/adversarial-element-named-xmlns-loads.xml'];
        yield 'elements 10000 with the root' => ['behaviour/adversarial-elements-10000-with-the-root-loads.xml'];
        yield 'greater than in text' => ['behaviour/adversarial-greater-than-in-text-loads.xml'];
        yield 'huge attribute value' => ['behaviour/adversarial-huge-attribute-value-loads.xml'];
        yield 'huge single text node' => ['behaviour/adversarial-huge-single-text-node-loads.xml'];
        yield 'id 128 bytes of two byte characters' => [
            'behaviour/adversarial-id-128-bytes-of-two-byte-characters-loads.xml',
        ];
        yield 'id attribute id on a saml element is not registered' => [
            'behaviour/adversarial-id-attribute-id-on-a-saml-element-is-not-registered-loads.xml',
        ];
        yield 'id case differs' => ['behaviour/adversarial-id-case-differs-loads.xml'];
        yield 'id character reference for underscore' => [
            'behaviour/adversarial-id-character-reference-for-underscore-loads.xml',
        ];
        yield 'id emoji' => ['behaviour/adversarial-id-emoji-loads.xml'];
        yield 'id middle dot inside' => ['behaviour/adversarial-id-middle-dot-inside-loads.xml'];
        yield 'id unicode precomposed and decomposed' => [
            'behaviour/adversarial-id-unicode-precomposed-and-decomposed-loads.xml',
        ];
        yield 'id zero width joiner inside' => ['behaviour/adversarial-id-zero-width-joiner-inside-loads.xml'];
        yield 'many namespace declarations one per element' => [
            'behaviour/adversarial-many-namespace-declarations-one-per-element-loads.xml',
        ];
        yield 'next line u0085 in text' => ['behaviour/adversarial-next-line-u0085-in-text-loads.xml'];
        yield 'pi xml stylesheet before root' => ['behaviour/adversarial-pi-xml-stylesheet-before-root-loads.xml'];
        yield 'standalone declaration' => ['behaviour/adversarial-standalone-declaration-loads.xml'];
        yield 'u 1fffe non character in text' => ['behaviour/adversarial-u-1fffe-non-character-in-text-loads.xml'];
        yield 'xinclude old namespace' => ['behaviour/adversarial-xinclude-old-namespace-loads.xml'];
        yield 'xinclude with xpointer' => ['behaviour/adversarial-xinclude-with-xpointer-loads.xml'];
        yield 'xml attribute unknown' => ['behaviour/adversarial-xml-attribute-unknown-loads.xml'];
        yield 'xml base and xml space and xml lang' => [
            'behaviour/adversarial-xml-base-and-xml-space-and-xml-lang-loads.xml',
        ];
        yield 'xml lang empty' => ['behaviour/adversarial-xml-lang-empty-loads.xml'];
        yield 'xml prefixed element' => ['behaviour/adversarial-xml-prefixed-element-loads.xml'];
        yield 'xmlns attribute value with entity amp' => [
            'behaviour/adversarial-xmlns-attribute-value-with-entity-amp-loads.xml',
        ];
        yield 'xmlns empty default on root' => ['behaviour/adversarial-xmlns-empty-default-on-root-loads.xml'];
        yield 'xmlns prefix rebound on a child' => ['behaviour/adversarial-xmlns-prefix-rebound-on-a-child-loads.xml'];
        yield 'xmlns prefix starting with xml' => ['behaviour/adversarial-xmlns-prefix-starting-with-xml-loads.xml'];
        yield 'xmlns prefix with a dot' => ['behaviour/adversarial-xmlns-prefix-with-a-dot-loads.xml'];
        yield 'xmlns uri scheme only' => ['behaviour/adversarial-xmlns-uri-scheme-only-loads.xml'];
        yield 'xmlns uri uppercase scheme' => ['behaviour/adversarial-xmlns-uri-uppercase-scheme-loads.xml'];
        yield 'xmlns uri with a fragment' => ['behaviour/adversarial-xmlns-uri-with-a-fragment-loads.xml'];
        yield 'xmlns xml prefix bound to its own uri' => [
            'behaviour/adversarial-xmlns-xml-prefix-bound-to-its-own-uri-loads.xml',
        ];
        yield 'xsi schema location' => ['behaviour/adversarial-xsi-schema-location-loads.xml'];
    }

    /**
     * I-8: two ID values that differ in case, or in Unicode composition (U+00E9 against e and U+0301), are two IDs;
     * the brick normalises nothing.
     */
    #[Test]
    public function itKeepsIdsDistinctThatANormalisationWouldMerge(): void
    {
        // Given
        $caseDiffers = Loaded::fixture('behaviour/adversarial-id-case-differs-loads.xml');
        $composition = Loaded::fixture('behaviour/adversarial-id-unicode-precomposed-and-decomposed-loads.xml');

        // When / Then
        static::assertNotSame($caseDiffers->elementById('_a'), $caseDiffers->elementById('_A'));
        static::assertNotSame($composition->elementById("\u{E9}"), $composition->elementById("e\u{301}"));
    }

    /**
     * I-4, section 8: a node of another document cannot be appended without importNode() or adoptNode(), which are
     * never called; the Dom API refuses it, so a foreign subtree never enters a document of the brick.
     */
    #[Test]
    public function itsDocumentsRefuseAForeignNodeAppendedToThem(): void
    {
        // Given
        $document = Loaded::document('<r/>');
        $foreign = Foreign::parse('<f xmlns="urn:f"/>')->documentElement;
        static::assertNotNull($foreign);

        // Then
        $this->expectException(DOMException::class);
        $this->expectExceptionMessageIs('Wrong Document Error');

        // When
        $document->root()->appendChild($foreign);
    }

    /**
     * Section 6.3 step 1: an apex inside a detached subtree is not connected either.
     */
    #[Test]
    public function itRefusesAnApexInsideADetachedSubtree(): void
    {
        // Given
        $document = Loaded::document('<r><a><b/></a></r>');
        $a = Nodes::childNamed($document->root(), 'a');
        $b = Nodes::childNamed($a, 'b');
        $document->root()->removeChild($a);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The apex is not connected to its document (section 6.3).');

        // When
        new Canonicalizer()->canonicalize($b, CanonicalizationMethod::Inclusive);
    }

    /**
     * Exclusive XML Canonicalization §4, section 13: a prefix of the list that names no declaration in scope, xml,
     * xmlns or a name with a colon, changes nothing.
     */
    #[Test]
    #[DataProvider('provideInertPrefixes')]
    public function itRendersNothingMoreForAnInertPrefixOfTheList(string $prefix): void
    {
        // Given
        $document = Loaded::document('<root xmlns="urn:d" xmlns:s="urn:s" xml:lang="fr"><s:a>t</s:a></root>');
        $apex = Nodes::childNamed($document->root(), 'a');

        // When
        $canonical = new Canonicalizer()->canonicalize(
            $apex,
            CanonicalizationMethod::Exclusive,
            new InclusiveNamespaces([$prefix]),
        );

        // Then
        static::assertSame('<s:a xmlns:s="urn:s">t</s:a>', $canonical->bytes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInertPrefixes(): iterable
    {
        yield 'xml' => ['xml'];
        yield 'xmlns' => ['xmlns'];
        yield 'a name with a colon' => ['s:x'];
        yield 'a prefix nobody declared' => ['nobody'];
    }

    /**
     * Section 13, measured: libxml reads an empty prefix as the default namespace, like #default; fromPrefixList()
     * never produces one, since it drops empty entries.
     */
    #[Test]
    public function itRendersTheDefaultNamespaceForAnEmptyPrefixOfTheList(): void
    {
        // Given
        $document = Loaded::document('<root xmlns="urn:d" xmlns:s="urn:s"><s:a>t</s:a></root>');
        $apex = Nodes::childNamed($document->root(), 'a');

        // When
        $canonical = new Canonicalizer()->canonicalize(
            $apex,
            CanonicalizationMethod::Exclusive,
            new InclusiveNamespaces(['']),
        );

        // Then
        static::assertSame('<s:a xmlns="urn:d" xmlns:s="urn:s">t</s:a>', $canonical->bytes);
        static::assertSame([], InclusiveNamespaces::fromPrefixList('   ')->prefixes);
    }

    /**
     * Section 7: a prefix list of ten thousand entries is no denial of service; the form is unchanged.
     */
    #[Test]
    public function itRendersTheSameFormForAHugePrefixList(): void
    {
        // Given
        $document = Loaded::document('<root xmlns="urn:d" xmlns:s="urn:s"><s:a>t</s:a></root>');
        $apex = Nodes::childNamed($document->root(), 'a');
        $prefixes = array_map(static fn (int $i): string => sprintf('p%d', $i), range(1, 10_000));

        // When
        $canonical = new Canonicalizer()->canonicalize(
            $apex,
            CanonicalizationMethod::Exclusive,
            new InclusiveNamespaces($prefixes),
        );

        // Then
        static::assertSame('<s:a xmlns:s="urn:s">t</s:a>', $canonical->bytes);
    }

    /**
     * I-11, section 6.6: an assertion wrapped in samlp:Extensions under another prefix of the same namespace is not
     * a child of the response, though the index, which is per document, reaches it by ID; what a verifier hands
     * over is the re-parse of the canonical bytes it hashed, never the document as it arrived.
     */
    #[Test]
    public function itDoesNotListAWrappedAssertionUnderAnotherPrefixAsAChild(): void
    {
        // Given
        $document = Loaded::document('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><samlp:Extensions><x:Assertion xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion" ID="_e"/></samlp:Extensions></samlp:Response>');

        // When
        $children = Children::named($document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion'));

        // Then
        static::assertSame([], $children);
        static::assertSame('Assertion', $document->elementById('_e')->localName);
    }

    /**
     * I-14: the comments of an excluded subtree are left out with it, and the others stay, with a method that
     * keeps comments.
     */
    #[Test]
    public function itLeavesTheCommentsOfAnExcludedSubtreeOut(): void
    {
        // Given
        $document = Loaded::document('<r><!--a--><s><!--in--></s><!--b--></r>');
        $excluded = Nodes::childNamed($document->root(), 's');

        // When
        $canonical = new Canonicalizer()->canonicalize(
            $document->root(),
            CanonicalizationMethod::InclusiveWithComments,
            InclusiveNamespaces::none(),
            [$excluded],
        );

        // Then
        static::assertSame('<r><!--a--><!--b--></r>', $canonical->bytes);
    }
}
