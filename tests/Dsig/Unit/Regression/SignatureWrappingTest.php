<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Regression;

use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, signature wrapping: "On Breaking SAML" (2012), eleven frameworks of fourteen, and CVE-2026-63182 in
 * litesaml/lightsaml in 2026. The rules: one ID space per document (Core I-8), the Signature a direct child of the
 * claimed element (D-1), the one reference resolved by identity to that element (D-2), the consumer reading the
 * reload of the hashed bytes and nothing else (D-10).
 */
final class SignatureWrappingTest extends TestCase
{
    /**
     * CVE-2026-63182, the first variant of 2012: the signed assertion moved elsewhere, an unsigned one with the same
     * ID where the consumer looks. Refused at load, before anything is verified.
     */
    #[Test]
    public function cve202663182TheWrappedAssertionWithTheSameIdIsRefusedAtLoad(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/xsw-assertion-in-extensions-same-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);

        // When
        Loaded::document($bytes);
    }

    /**
     * CVE-2026-63182, the second variant: the unsigned assertion given a new ID and a copy of the Signature; the
     * reference still names the wrapped original, not the claimed element.
     */
    #[Test]
    public function cve202663182TheClaimedElementIsNotTheOneTheReferenceNames(): void
    {
        // Given
        $document = Loaded::fixture('hostile/xsw-assertion-in-extensions-new-id-refused.xml');
        $claimed = $document->elementById('_evil-e1f2g3');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // Then
        $this->expectException(WrongReference::class);
        $this->expectExceptionMessageIs('The reference does not name the claimed element (D-2).');

        // When
        $verifier->verify($claimed, $keys);
    }
}
