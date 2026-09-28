<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit;

use function array_fill;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.2, D-14: one to sixteen trusted keys, in the consumer's order.
 */
final class VerificationKeysTest extends TestCase
{
    #[Test]
    public function itHoldsTheKeysInOrder(): void
    {
        // Given
        $first = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));
        $second = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/stranger-certificate.pem'));

        // When
        $keys = new VerificationKeys([$first, $second]);

        // Then
        static::assertSame([$first, $second], $keys->keys);
    }

    /**
     * §9.2 row 34, D-14: seventeen keys.
     */
    #[Test]
    public function itRefusesMoreThanSixteenKeys(): void
    {
        // Given
        $key = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The verification keys are one to maxVerificationKeys, 16 (D-14).');

        // When
        new VerificationKeys(array_fill(0, 17, $key));
    }

    /**
     * D-14: sixteen keys are the bound, not over it.
     */
    #[Test]
    public function itHoldsSixteenKeys(): void
    {
        // Given
        $key = VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem'));

        // When
        $keys = new VerificationKeys(array_fill(0, 16, $key));

        // Then
        static::assertCount(16, $keys->keys);
    }

    /**
     * D-14: no key at all is a programming error.
     */
    #[Test]
    public function itRefusesNoKey(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The verification keys are one to maxVerificationKeys, 16 (D-14).');

        // When
        new VerificationKeys([]);
    }
}
