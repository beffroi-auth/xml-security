<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Regression;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, the structure read loosely: CVE-2025-29774 and CVE-2025-29775, xml-crypto before 6.0.1 verified
 * documents holding several SignedInfo elements or a DigestValue split by a comment; CVE-2023-49087, the
 * validation of SignedInfo in simplesamlphp/xml-security. The rule: three children of Signature, three of
 * SignedInfo, one Reference, each read once and counted (D-9), and the signature verified over the canonical
 * SignedInfo before any digest is read (D-6).
 */
final class LooseStructureTest extends TestCase
{
    private Verifier $verifier;

    private VerificationKeys $keys;

    protected function setUp(): void
    {
        $this->verifier = new Verifier(new Loader(Stack::idAttributes()));
        $this->keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);
    }

    /**
     * CVE-2025-29774: two SignedInfo elements, the second one the attacker's, are a refusal, not a choice.
     */
    #[Test]
    public function cve202529774TwoSignedInfoAreRefused(): void
    {
        // Given
        $document = Loaded::fixture('hostile/two-signedinfo-refused.xml');
        $claimed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A Signature holds exactly one SignedInfo (D-9).');

        // When
        $this->verifier->verify($claimed, $this->keys);
    }

    /**
     * CVE-2025-29775: a DigestValue split by a comment reads as one value, and an altered one is caught by the
     * signature over SignedInfo, never by a comparison of what the attacker wrote.
     */
    #[Test]
    public function cve202529775ADigestValueSplitByACommentVerifiesAndAnAlteredOneDoesNot(): void
    {
        // Given
        $split = Loaded::fixture('behaviour/digest-value-comment-split-loads.xml');
        $altered = Loaded::fixture('hostile/digest-value-altered-refused.xml');

        // When
        $verified = $this->verifier->verify($split->elementById('_assertion-d4e5f6'), $this->keys);

        // Then
        static::assertSame('Assertion', $verified->document->root()->localName);
        $this->expectException(SignatureMismatch::class);
        $this->verifier->verify($altered->elementById('_assertion-d4e5f6'), $this->keys);
    }

    /**
     * CVE-2023-49087: a SignedInfo holding a second Reference, whatever it names, is a refusal.
     */
    #[Test]
    public function cve202349087ASecondReferenceIsRefused(): void
    {
        // Given
        $document = Loaded::fixture('hostile/two-references-refused.xml');
        $claimed = $document->elementById('_assertion-d4e5f6');

        // Then
        $this->expectException(MalformedSignature::class);
        $this->expectExceptionMessageIs('A SignedInfo holds exactly one Reference (D-2).');

        // When
        $this->verifier->verify($claimed, $this->keys);
    }
}
