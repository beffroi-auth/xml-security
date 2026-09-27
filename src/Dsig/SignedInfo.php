<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Internal\Names;
use Beffroi\Xml\Dsig\Internal\Structure;
use Dom\Element;

/**
 * The ds:SignedInfo of a Signature, read strictly (section 5.3): an exclusive canonicalization method (D-4), a
 * signature method of the closed list (D-5), exactly one Reference (D-2), and no other child (D-9).
 */
final readonly class SignedInfo
{
    public function __construct(
        public Element $element,
        public CanonicalizationMethod $canonicalizationMethod,
        public InclusiveNamespaces $inclusiveNamespaces,
        public SignatureAlgorithm $signatureMethod,
        public Reference $reference,
    ) {
    }

    /**
     * @throws MalformedSignature
     * @throws Exception\UnknownSignatureAlgorithm
     * @throws Exception\UnknownDigestAlgorithm
     * @throws Exception\LimitExceeded
     */
    public static function of(Element $element): self
    {
        $canonicalizationMethod = Names::dsig('CanonicalizationMethod');
        $signatureMethod = Names::dsig('SignatureMethod');
        $reference = Names::dsig('Reference');
        Structure::refuseOtherChildren(
            $element,
            [$canonicalizationMethod, $signatureMethod, $reference],
            'A SignedInfo holds a child other than CanonicalizationMethod, SignatureMethod and Reference (D-9).',
        );
        [$method, $inclusiveNamespaces] = Reference::exclusiveCanonicalization(
            Structure::one(
                $element,
                $canonicalizationMethod,
                'A SignedInfo holds exactly one CanonicalizationMethod (D-9).',
            ),
            'The canonicalization method is not exclusive (D-4).',
            'A CanonicalizationMethod holds nothing but an InclusiveNamespaces (D-9).',
        );
        $algorithm = self::signatureMethod(
            Structure::one($element, $signatureMethod, 'A SignedInfo holds exactly one SignatureMethod (D-9).'),
        );

        return new self(
            $element,
            $method,
            $inclusiveNamespaces,
            $algorithm,
            Reference::of(Structure::one($element, $reference, 'A SignedInfo holds exactly one Reference (D-2).')),
        );
    }

    /**
     * @throws MalformedSignature
     * @throws Exception\UnknownSignatureAlgorithm
     */
    private static function signatureMethod(Element $signatureMethod): SignatureAlgorithm
    {
        $algorithm = SignatureAlgorithm::fromUri(
            Attributes::optional(
                $signatureMethod,
                Names::attribute('Algorithm'),
            ) ?? throw new MalformedSignature('A SignatureMethod names its Algorithm (D-5).'),
        );
        Structure::none($signatureMethod, 'A SignatureMethod holds no child (D-9).');

        return $algorithm;
    }
}
