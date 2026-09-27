<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Internal\Base64;
use Beffroi\Xml\Dsig\Internal\Names;
use Beffroi\Xml\Dsig\Internal\Structure;
use Dom\Element;
use function sprintf;
use function strlen;

/**
 * The ds:Signature element read strictly (section 5.3, D-9), nothing computed: SignedInfo, SignatureValue and an
 * optional KeyInfo that is never read (D-7); Object and everything else refused. A consumer may read a signature
 * without verifying it; only Verifier verifies.
 */
final readonly class Signature
{
    /**
     * Section 7: the decoded SignatureValue, from an RSA-2048 signature to an RSA-8192 one.
     */
    public const int MIN_SIGNATURE_BYTES = 256;

    public const int MAX_SIGNATURE_BYTES = 1024;

    public function __construct(
        public Element $element,
        public SignedInfo $signedInfo,
        public string $signatureValue,
    ) {
    }

    /**
     * @throws MalformedSignature when the structure, an algorithm, a transform, a URI or a base64 text is not what
     *                            section 5.3 says
     * @throws Exception\UnknownSignatureAlgorithm
     * @throws Exception\UnknownDigestAlgorithm
     * @throws LimitExceeded
     * @throws ForeignNode when $element is not of a document of the brick
     */
    public static function of(Element $element): self
    {
        Document::owning($element);
        if (! Names::dsig('Signature')->matches($element)) {
            throw new MalformedSignature('The element is not a ds:Signature (D-9).');
        }
        $signedInfo = Names::dsig('SignedInfo');
        $signatureValue = Names::dsig('SignatureValue');
        $keyInfo = Names::dsig('KeyInfo');
        Structure::refuseOtherChildren(
            $element,
            [$signedInfo, $signatureValue, $keyInfo],
            'A Signature holds a child other than SignedInfo, SignatureValue and KeyInfo (D-9).',
        );
        Structure::optional($element, $keyInfo, 'A Signature holds at most one KeyInfo (D-9).');
        $signed = SignedInfo::of(
            Structure::one($element, $signedInfo, 'A Signature holds exactly one SignedInfo (D-9).'),
        );
        $value = Base64::decode(Text::of(
            Structure::one($element, $signatureValue, 'A Signature holds exactly one SignatureValue (D-9).'),
        ));
        if (strlen($value) < self::MIN_SIGNATURE_BYTES || strlen($value) > self::MAX_SIGNATURE_BYTES) {
            throw new LimitExceeded(sprintf(
                'A SignatureValue is not between %d and maxSignatureValueBytes, %d bytes (D-14).',
                self::MIN_SIGNATURE_BYTES,
                self::MAX_SIGNATURE_BYTES,
            ));
        }

        return new self($element, $signed, $value);
    }
}
