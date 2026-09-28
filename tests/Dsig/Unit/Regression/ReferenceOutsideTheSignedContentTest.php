<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Regression;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, a reference outside the signed content: CVE-2019-3465, xmlseclibs before 3.0.4 verified a signature
 * whose reference did not resolve inside the signed content. The rule: a reference is "#" and an NCName, resolved
 * to the claimed element by identity; empty, xpointer and external references are refused (D-2).
 */
final class ReferenceOutsideTheSignedContentTest extends TestCase
{
    /**
     * CVE-2019-3465: an external URI, an empty URI and an xpointer form are refused before anything is computed.
     */
    #[Test]
    #[TestWith(['reference-uri-external-refused.xml'], 'an external URI')]
    #[TestWith(['reference-uri-empty-refused.xml'], 'an empty URI')]
    #[TestWith(['reference-uri-xpointer-refused.xml'], 'an xpointer form')]
    public function cve20193465AReferenceThatIsNotAnIdOfTheDocumentIsRefused(string $fixture): void
    {
        // Given
        $document = Loaded::fixture('hostile/' . $fixture);
        $claimed = $document->elementById('_assertion-d4e5f6');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A Reference names the claimed element by its ID, "#" followed by an NCName (D-2).');

        // When
        $verifier->verify($claimed, $keys);
    }
}
