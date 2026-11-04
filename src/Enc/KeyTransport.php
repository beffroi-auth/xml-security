<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Structure;
use Dom\Element;

/**
 * E-1: the DigestMethod and the MGF of an rsa-oaep must name one hash, the digest parameter of PHP's RSA
 * functions setting both.
 */
final readonly class KeyTransport
{
    /**
     * XML Encryption 1.0 §5.4.2
     */
    public const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /**
     * XML Encryption 1.1 §5.5.2
     */
    public const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    public function __construct(
        public OaepHash $hash,
    ) {
    }

    public static function mgf1p(): self
    {
        return new self(OaepHash::Sha1);
    }

    /**
     * Section 6.1 step 2: rsa-oaep-mgf1p takes an optional DigestMethod of SHA-1, as Shibboleth and ADFS write one.
     *
     * @throws UnknownKeyTransport for every other Algorithm, and when the hashes differ
     * @throws MalformedEncryption for an element that is not an xenc:EncryptionMethod, an OAEPparams, an MGF under
     *                             rsa-oaep-mgf1p, or any other child
     * @throws ForeignNode
     */
    public static function of(Element $encryptionMethod): self
    {
        Document::owning($encryptionMethod);
        if (! Names::xenc('EncryptionMethod')->matches($encryptionMethod)) {
            throw new MalformedEncryption('The element is not an xenc:EncryptionMethod (E-5).');
        }
        $algorithm = Attributes::optional(
            $encryptionMethod,
            Names::attribute('Algorithm'),
        ) ?? throw new MalformedEncryption('An EncryptionMethod names its Algorithm (E-5).');

        return match ($algorithm) {
            self::RSA_OAEP_MGF1P => self::mgf1pOf($encryptionMethod),
            self::RSA_OAEP => self::oaepOf($encryptionMethod),
            default => throw new UnknownKeyTransport('The key transport is not RSA-OAEP: PKCS#1 v1.5, key wrapping and key agreement are refused by name (E-1).'),
        };
    }

    public function uri(): string
    {
        return $this->hash === OaepHash::Sha1 ? self::RSA_OAEP_MGF1P : self::RSA_OAEP;
    }

    /**
     * @throws MalformedEncryption
     * @throws UnknownKeyTransport
     */
    private static function mgf1pOf(Element $encryptionMethod): self
    {
        $digestMethod = Names::dsig('DigestMethod');
        Structure::refuseOtherChildren(
            $encryptionMethod,
            [$digestMethod],
            'An EncryptionMethod of rsa-oaep-mgf1p holds nothing but a DigestMethod (E-5).',
        );
        $digest = Structure::optional(
            $encryptionMethod,
            $digestMethod,
            'An EncryptionMethod holds at most one DigestMethod (E-5).',
        );
        if ($digest instanceof Element && OaepHash::fromDigestUri(self::algorithmOf($digest)) !== OaepHash::Sha1) {
            throw new UnknownKeyTransport('The DigestMethod of rsa-oaep-mgf1p names a hash other than SHA-1, the one MGF1 uses under that name (E-1).');
        }

        return self::mgf1p();
    }

    /**
     * @throws MalformedEncryption
     * @throws UnknownKeyTransport
     */
    private static function oaepOf(Element $encryptionMethod): self
    {
        $digestMethod = Names::dsig('DigestMethod');
        $mgf = Names::xenc11('MGF');
        Structure::refuseOtherChildren(
            $encryptionMethod,
            [$digestMethod, $mgf],
            'An EncryptionMethod of rsa-oaep holds nothing but a DigestMethod and an MGF (E-5).',
        );
        $digest = Structure::optional(
            $encryptionMethod,
            $digestMethod,
            'An EncryptionMethod holds at most one DigestMethod (E-5).',
        );
        $maskGeneration = Structure::optional(
            $encryptionMethod,
            $mgf,
            'An EncryptionMethod holds at most one MGF (E-5).',
        );
        $hash = $digest instanceof Element ? OaepHash::fromDigestUri(self::algorithmOf($digest)) : OaepHash::Sha1;
        $mgfHash = $maskGeneration instanceof Element
            ? OaepHash::fromMgfUri(self::algorithmOf($maskGeneration))
            : OaepHash::Sha1;
        if ($hash !== $mgfHash) {
            throw new UnknownKeyTransport('The DigestMethod and the MGF of rsa-oaep name different hashes, which PHP cannot express (E-1).');
        }

        return new self($hash);
    }

    /**
     * @throws MalformedEncryption
     */
    private static function algorithmOf(Element $element): string
    {
        Structure::none($element, 'A DigestMethod or an MGF holds no child (E-5).');

        return (
            Attributes::optional(
                $element,
                Names::attribute('Algorithm'),
            ) ?? throw new MalformedEncryption('A DigestMethod or an MGF names its Algorithm (E-5).')
        );
    }
}
