<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\Exception\UnknownKeyTransport;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Structure;
use Dom\Element;

/**
 * RSA-OAEP with one hash for the OAEP mask and for MGF1 (E-1), the one key transport family the namespace reads
 * and writes: rsa-oaep-mgf1p of XML Encryption 1.0, SHA-1 by definition, and rsa-oaep of XML Encryption 1.1, whose
 * DigestMethod and MGF must name the same hash since the digest parameter of PHP's RSA functions sets both
 * (specification, section 13). PKCS#1 v1.5, key wrapping and key agreement are refused by name, before anything is
 * decoded: a peer that accepts the old next to the new is broken as if it accepted only the old.
 */
final readonly class KeyTransport
{
    /**
     * XML Encryption 1.0 §5.4.2: RSAES-OAEP with SHA-1 for the hash and for MGF1.
     */
    public const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /**
     * XML Encryption 1.1 §5.5.2: RSAES-OAEP whose DigestMethod and MGF name the hash, SHA-1 when absent.
     */
    public const string RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';

    /**
     * @param OaepHash $hash for the OAEP mask and for MGF1 alike
     */
    public function __construct(
        public OaepHash $hash,
    ) {
    }

    /**
     * SHA-1, what every interoperability target produces and accepts.
     */
    public static function mgf1p(): self
    {
        return new self(OaepHash::Sha1);
    }

    /**
     * The EncryptionMethod of an EncryptedKey, read strictly (section 6.1 step 2): rsa-oaep-mgf1p with an optional
     * DigestMethod of SHA-1, the one hash MGF1 uses under that name and the child Shibboleth and ADFS write, or
     * rsa-oaep with an optional DigestMethod and an optional MGF naming the same hash, SHA-1 when absent.
     *
     * @throws UnknownKeyTransport for every other Algorithm, and when the hashes differ
     * @throws MalformedEncryption for an OAEPparams, an MGF under rsa-oaep-mgf1p, or any other child
     */
    public static function of(Element $encryptionMethod): self
    {
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

    /**
     * The URI written into an EncryptionMethod: rsa-oaep-mgf1p for SHA-1, rsa-oaep with a DigestMethod and an MGF
     * otherwise.
     */
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
     * The Algorithm a DigestMethod or an MGF names, the element holding no child.
     *
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
