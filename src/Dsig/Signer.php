<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Core\Exception\AmbiguousChild;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function base64_encode;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Internal\Registry;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\Internal\Names;
use Beffroi\Xml\Dsig\Internal\Pem;
use function chunk_split;
use Dom\Element;
use Dom\XMLDocument;
use InvalidArgumentException;
use SensitiveParameter;
use function rtrim;

/**
 * Section 6.2
 *
 * The document is serialized and loaded again first, so that what is hashed is what the peer will parse (D-12).
 */
final readonly class Signer
{
    /**
     * @param Loader $loader the consumer's, for the reload of D-12
     */
    public function __construct(
        private Loader $loader,
        private Serializer $serializer = new Serializer(),
        private Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {
    }

    /**
     * The document loaded again, with the ds:Signature inserted after the child named $after or first.
     *
     * @param ?string $certificatePem one PEM certificate, carried in the KeyInfo (D-17)
     *
     * @throws InvalidKey
     * @throws AlgorithmUnavailable
     * @throws UnknownId
     * @throws MissingChild
     * @throws AmbiguousChild
     * @throws RefusedXml
     * @throws Exception\SigningFailed
     * @throws InvalidArgumentException when $method is not exclusive, or the element already holds a ds:Signature
     */
    public function sign(
        Document $document,
        string $id,
        SigningKeyInterface $key,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        ?Name $after = null,
        #[SensitiveParameter]
        ?string $certificatePem = null,
        CanonicalizationMethod $method = CanonicalizationMethod::Exclusive,
        DigestAlgorithm $digest = DigestAlgorithm::Sha256,
    ): Document {
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot produce RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');
        }
        if (! $method->isExclusive()) {
            throw new InvalidArgumentException('The canonicalization method is exclusive, with or without comments (D-4).');
        }
        $certificate = $certificatePem === null ? null : $this->certificate($certificatePem);
        $loaded = $this->loader->load($this->serializer->serialize($document));
        $element = $loaded->elementById($id);
        if (Children::named($element, Names::dsig('Signature')) !== []) {
            throw new InvalidArgumentException('The element already holds a ds:Signature, and a second one is what D-1 refuses (D-1).');
        }
        $before = $after instanceof Name ? Children::one($element, $after)->nextSibling : $element->firstChild;
        // Without comments: the node-set of a same-document reference omits them (section 6.1 step 8).
        $digestValue = $digest->hash(
            $this->canonicalizer->canonicalize(
                $element,
                CanonicalizationMethod::Exclusive,
                InclusiveNamespaces::none(),
            )->bytes,
        );
        $xml = Registry::xmlOf($loaded);
        $signature = $xml->createElementNS(Names::DSIG, 'ds:Signature');
        $signedInfo = $this->child($xml, $signature, 'SignedInfo');
        $this->child($xml, $signedInfo, 'CanonicalizationMethod')->setAttribute('Algorithm', $method->value);
        $this->child($xml, $signedInfo, 'SignatureMethod')->setAttribute('Algorithm', $algorithm->value);
        $reference = $this->child($xml, $signedInfo, 'Reference');
        $reference->setAttribute('URI', '#' . $id);
        $transforms = $this->child($xml, $reference, 'Transforms');
        $this->child($xml, $transforms, 'Transform')->setAttribute('Algorithm', Names::ENVELOPED_SIGNATURE);
        $this->child($xml, $transforms, 'Transform')->setAttribute('Algorithm', $method->value);
        $this->child($xml, $reference, 'DigestMethod')->setAttribute('Algorithm', $digest->value);
        $this->child($xml, $reference, 'DigestValue')->appendChild($xml->createTextNode(base64_encode($digestValue)));
        $signatureValue = $this->child($xml, $signature, 'SignatureValue');
        $element->insertBefore($signature, $before);
        $signatureValue->appendChild($xml->createTextNode($this->lines($key->sign(
            $this->canonicalizer->canonicalize($signedInfo, $method, InclusiveNamespaces::none())->bytes,
            $algorithm,
        ))));
        if ($certificate !== null) {
            $data = $this->child($xml, $this->child($xml, $signature, 'KeyInfo'), 'X509Data');
            $this->child($xml, $data, 'X509Certificate')->appendChild($xml->createTextNode($certificate));
        }

        return $loaded;
    }

    /**
     * Exactly one CERTIFICATE block, written again from its decoded bytes, so that neither a private key nor a
     * bundle nor a chain reaches the peer (D-17).
     *
     * @throws InvalidKey
     */
    private function certificate(#[SensitiveParameter] string $pem): string
    {
        return base64_encode(
            Pem::block(
                $pem,
                'CERTIFICATE',
            ) ?? throw new InvalidKey('The certificate is one PEM block of type CERTIFICATE and nothing else (D-17).'),
        );
    }

    /**
     * Prefixed, by the rule of core.md section 6.5 for a built tree.
     */
    private function child(XMLDocument $xml, Element $parent, string $local): Element
    {
        $child = $xml->createElementNS(Names::DSIG, 'ds:' . $local);
        $parent->appendChild($child);

        return $child;
    }

    /**
     * Base64 with a line break every 76 characters, as the interoperability targets write it (section 6.2).
     */
    private function lines(string $bytes): string
    {
        return rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n");
    }
}
