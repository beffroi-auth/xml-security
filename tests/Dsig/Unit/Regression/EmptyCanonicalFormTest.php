<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Regression;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the empty canonical form: CVE-2025-66578, xmlseclibs hashed the empty string libxml returned when
 * canonicalization failed. The rule lives in Core (I-13) and Dsig inherits it (D-11): the canonical forms of
 * SignedInfo and of the element come from Canonicalizer, which refuses false and the empty string, so nothing here
 * ever hashes nothing.
 */
final class EmptyCanonicalFormTest extends TestCase
{
    /**
     * CVE-2025-66578, §9.2 row 39: the bytes a verification hashed are never empty; an element always renders its
     * start tag, and the case of a failing canonicalization is Core's, tested there.
     */
    #[Test]
    public function cve202566578TheHashedBytesAreNeverEmpty(): void
    {
        // Given
        $document = Loaded::fixture('vectors/response-assertion-rsa-sha256.xml');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // When
        $verified = $verifier->verify($document->elementById('_assertion-d4e5f6'), $keys);

        // Then
        static::assertNotSame('', $verified->canonical->bytes);
        static::assertStringStartsWith('<saml:Assertion', $verified->canonical->bytes);
    }
}
