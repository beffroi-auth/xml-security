<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\UnknownCanonicalizationMethod;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\NcName;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\MalformedSignature;
use Beffroi\Xml\Dsig\Internal\Base64;
use Beffroi\Xml\Dsig\Internal\Names;
use Beffroi\Xml\Dsig\Internal\Structure;
use function count;
use Dom\Element;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * The one ds:Reference of a SignedInfo, read strictly (section 5.3): a same-document URI of "#" and an NCName
 * (D-2), the enveloped signature transform then an exclusive canonicalization and nothing else (D-3, D-4), a
 * digest method of the closed list (D-5), a digest value of exactly the digest's length (D-8, D-14).
 */
final readonly class Reference
{
    /**
     * Section 7: the prefixes of a PrefixList.
     */
    public const int MAX_PREFIXES = 32;

    public function __construct(
        public string $id,
        public CanonicalizationMethod $canonicalization,
        public InclusiveNamespaces $inclusiveNamespaces,
        public DigestAlgorithm $digestMethod,
        public string $digestValue,
    ) {
    }

    /**
     * @throws MalformedSignature when the structure, a URI, a transform or a value is not what section 5.3 says
     * @throws Exception\UnknownDigestAlgorithm
     * @throws LimitExceeded
     * @throws ForeignNode when $element is not of a document of the brick
     */
    public static function of(Element $element): self
    {
        Document::owning($element);
        if (Attributes::optional($element, Names::attribute('Type')) !== null) {
            throw new MalformedSignature('A Reference carries no Type (D-2).');
        }
        $uri = Attributes::optional($element, Names::attribute('URI')) ?? '';
        if (! str_starts_with($uri, '#') || ! NcName::is(substr($uri, 1))) {
            throw new MalformedSignature('A Reference names the claimed element by its ID, "#" followed by an NCName (D-2).');
        }
        $transforms = Names::dsig('Transforms');
        $digestMethod = Names::dsig('DigestMethod');
        $digestValue = Names::dsig('DigestValue');
        Structure::refuseOtherChildren(
            $element,
            [$transforms, $digestMethod, $digestValue],
            'A Reference holds a child other than Transforms, DigestMethod and DigestValue (D-9).',
        );
        [$canonicalization, $inclusiveNamespaces] = self::transforms(
            Structure::one($element, $transforms, 'A Reference holds exactly one Transforms (D-3).'),
        );
        $algorithm = self::digestMethod(
            Structure::one($element, $digestMethod, 'A Reference holds exactly one DigestMethod (D-9).'),
        );
        $digest = Base64::decode(Structure::text(
            Structure::one($element, $digestValue, 'A Reference holds exactly one DigestValue (D-9).'),
            'A DigestValue holds nothing but text (D-9).',
        ));
        if (strlen($digest) !== $algorithm->length()) {
            throw new MalformedSignature('A DigestValue is not the length of its digest (D-14).');
        }

        return new self(substr($uri, 1), $canonicalization, $inclusiveNamespaces, $algorithm, $digest);
    }

    /**
     * The enveloped signature transform then an exclusive canonicalization, in that order, nothing else (D-3).
     *
     * @throws MalformedSignature
     * @throws LimitExceeded
     * @return array{CanonicalizationMethod, InclusiveNamespaces}
     */
    private static function transforms(Element $transforms): array
    {
        $message = 'The transforms are the enveloped signature transform then an exclusive canonicalization, and nothing else (D-3).';
        $list = Children::all($transforms);
        $transform = Names::dsig('Transform');
        if (count($list) !== 2 || ! $transform->matches($list[0]) || ! $transform->matches($list[1])) {
            throw new MalformedSignature($message);
        }
        if (Attributes::optional($list[0], Names::attribute('Algorithm')) !== Names::ENVELOPED_SIGNATURE) {
            throw new MalformedSignature($message);
        }
        Structure::none($list[0], 'The enveloped signature transform holds no child (D-9).');

        return self::exclusiveCanonicalization(
            $list[1],
            $message,
            'A canonicalization transform holds nothing but an InclusiveNamespaces (D-9).',
        );
    }

    /**
     * An element whose Algorithm is an exclusive canonicalization (D-4), with an optional InclusiveNamespaces child
     * carrying a bounded PrefixList (D-14): the second transform of a reference, and the CanonicalizationMethod of
     * a SignedInfo.
     *
     * @param string $notExclusive the refusal when the algorithm is missing, unknown or not exclusive
     * @param string $otherChild the refusal when a child is not an InclusiveNamespaces
     *
     * @throws MalformedSignature
     * @throws LimitExceeded
     * @return array{CanonicalizationMethod, InclusiveNamespaces}
     */
    public static function exclusiveCanonicalization(Element $element, string $notExclusive, string $otherChild): array
    {
        try {
            $method = CanonicalizationMethod::fromUri(
                Attributes::optional($element, Names::attribute('Algorithm')) ?? '',
            );
        } catch (UnknownCanonicalizationMethod) {
            throw new MalformedSignature($notExclusive);
        }
        if (! $method->isExclusive()) {
            throw new MalformedSignature($notExclusive);
        }
        Structure::refuseOtherChildren($element, [Names::inclusiveNamespaces()], $otherChild);
        $inclusiveNamespaces = Structure::optional($element, Names::inclusiveNamespaces(), $otherChild);
        if (! $inclusiveNamespaces instanceof Element) {
            return [$method, InclusiveNamespaces::none()];
        }
        Structure::none($inclusiveNamespaces, 'An InclusiveNamespaces holds no child (D-9).');
        $prefixList = Attributes::optional(
            $inclusiveNamespaces,
            Names::attribute('PrefixList'),
        ) ?? throw new MalformedSignature('An InclusiveNamespaces names its PrefixList (D-9).');
        $prefixes = InclusiveNamespaces::fromPrefixList($prefixList);
        if (count($prefixes->prefixes) > self::MAX_PREFIXES) {
            throw new LimitExceeded(sprintf(
                'A PrefixList holds more prefixes than maxPrefixes, %d (D-14).',
                self::MAX_PREFIXES,
            ));
        }

        return [$method, $prefixes];
    }

    /**
     * @throws MalformedSignature
     * @throws Exception\UnknownDigestAlgorithm
     */
    private static function digestMethod(Element $digestMethod): DigestAlgorithm
    {
        Structure::none($digestMethod, 'A DigestMethod holds no child (D-9).');

        return DigestAlgorithm::fromUri(
            Attributes::optional(
                $digestMethod,
                Names::attribute('Algorithm'),
            ) ?? throw new MalformedSignature('A DigestMethod names its Algorithm (D-5).'),
        );
    }
}
