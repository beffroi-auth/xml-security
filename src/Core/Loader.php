<?php

declare(strict_types=1);

namespace Beffroi\Xml\Core;

use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\LimitExceeded;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Core\Exception\ParserDiagnostic;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Internal\Inspector;
use Beffroi\Xml\Core\Internal\Registry;
use function defined;
use Dom\XMLDocument;
use DOMException;
use function libxml_clear_errors;
use function libxml_get_errors;
use const LIBXML_NO_XXE;
use const LIBXML_NONET;
use function libxml_use_internal_errors;
use LibXMLError;
use SensitiveParameter;
use function preg_match;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;

/**
 * Section 6.1
 */
final readonly class Loader
{
    private Inspector $inspector;

    public function __construct(
        private IdAttributes $idAttributes,
        private Limits $limits = new Limits(),
    ) {
        $this->inspector = new Inspector($this->idAttributes, $this->limits);
    }

    /**
     * The bytes are a SensitiveParameter: a decrypted plaintext stays out of the traces of its refusal.
     *
     * @throws RefusedXml
     */
    public function load(#[SensitiveParameter] string $bytes): Document
    {
        if (strlen($bytes) > $this->limits->maxBytes) {
            throw new LimitExceeded(sprintf(
                'The input is larger than maxBytes, %d bytes (I-7).',
                $this->limits->maxBytes,
            ));
        }
        if (str_starts_with($bytes, "\xFE\xFF") || str_starts_with($bytes, "\xFF\xFE") || str_starts_with($bytes, "\x00\x00\xFE\xFF")) {
            throw new EncodingRefused('The input starts with a UTF-16 or UTF-32 byte order mark (I-5).');
        }
        if (preg_match('//u', $bytes) !== 1) {
            throw new EncodingRefused('The input is not valid UTF-8 (I-5).');
        }
        // Wherever it sits, in a comment or a CDATA section too: the false positive is accepted (section 6.1).
        if (str_contains($bytes, '<!DOCTYPE')) {
            throw new DoctypeRefused('The input contains a document type declaration (I-1).');
        }
        if ($bytes === '') {
            throw new MalformedXml('The input is empty (I-3).');
        }
        $xml = $this->parse($bytes);

        return Registry::register($xml, $this->inspector->inspect($xml));
    }

    /**
     * I-2, I-3
     *
     * @throws MalformedXml|ParserDiagnostic
     */
    private function parse(string $bytes): XMLDocument
    {
        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();
        try {
            try {
                // LIBXML_NO_XXE exists from libxml 2.13 only: the builds of section 13 do not define it.
                $document = XMLDocument::createFromString(
                    $bytes,
                    LIBXML_NONET | (defined('LIBXML_NO_XXE') ? LIBXML_NO_XXE : 0),
                );
            } catch (DOMException $exception) {
                throw new MalformedXml(
                    $this->describe('libxml refused the input', libxml_get_errors()[0] ?? null),
                    $exception->getCode(),
                    previous: $exception,
                );
            }
            $diagnostics = libxml_get_errors();
            if ($diagnostics !== []) {
                throw new ParserDiagnostic($this->describe('libxml reported a diagnostic', $diagnostics[0]));
            }

            return $document;
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }

    /**
     * Never libxml's message, which quotes the input (I-16).
     */
    private function describe(string $what, ?LibXMLError $error): string
    {
        return sprintf(
            '%s: error %d, level %d, at line %d, column %d (I-3).',
            $what,
            $error->code ?? 0,
            $error->level ?? 0,
            $error->line ?? 0,
            $error->column ?? 0,
        );
    }
}
