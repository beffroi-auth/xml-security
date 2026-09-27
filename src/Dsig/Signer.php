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
use Beffroi\Xml\Dsig\Internal\Names;
use function chunk_split;
use Dom\Element;
use Dom\XMLDocument;
use InvalidArgumentException;
use function preg_replace;
use function rtrim;

/**
 * Signing in the order of section 6.2: the document serialized and loaded again, so that what is hashed is what
 * the peer will parse (D-12); the element canonicalized without comments for the digest; a ds:Signature built with
 * a prefix on every element, inserted after the child the consumer names or first; SignedInfo canonicalized where
 * it stands and signed through the port; the loaded, signed Document returned, the one the consumer serializes.
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
     * The document, loaded again, with a ds:Signature over the element of ID $id inserted as its child, after the
     * child named $after or as its first child.
     *
     * @param ?string $certificatePem when given, a KeyInfo/X509Data/X509Certificate carrying it, for peers that want the hint
     *
     * @throws AlgorithmUnavailable a PSS scheme on a build without OPENSSL_PKCS1_PSS_PADDING
     * @throws UnknownId when the loaded document holds no element of that ID
     * @throws MissingChild when $after names no child of the element
     * @throws AmbiguousChild when $after names several
     * @throws RefusedXml what Core's serializer and loader refuse of the document (core.md 6.5, 6.1)
     * @throws Exception\SigningFailed when the primitive fails
     * @throws InvalidArgumentException when $method is not exclusive (D-4)
     */
    public function sign(
        Document $document,
        string $id,
        SigningKeyInterface $key,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        ?Name $after = null,
        ?string $certificatePem = null,
        CanonicalizationMethod $method = CanonicalizationMethod::Exclusive,
        DigestAlgorithm $digest = DigestAlgorithm::Sha256,
    ): Document {
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot produce RSASSA-PSS: OPENSSL_PKCS1_PSS_PADDING is undefined before PHP 8.5 (section 13).');
        }
        if (! $method->isExclusive()) {
            throw new InvalidArgumentException('The canonicalization method is exclusive, with or without comments (D-4).');
        }
        $loaded = $this->loader->load($this->serializer->serialize($document));
        $element = $loaded->elementById($id);
        $before = $after instanceof Name ? Children::one($element, $after)->nextSibling : $element->firstChild;
        // always without comments: the node-set of a same-document reference omits them (section 6.1 step 8)
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
        if ($certificatePem !== null) {
            $data = $this->child($xml, $this->child($xml, $signature, 'KeyInfo'), 'X509Data');
            $this->child($xml, $data, 'X509Certificate')->appendChild($xml->createTextNode(
                preg_replace('~-----[A-Z ]+-----|\s~', '', $certificatePem) ?? '',
            ));
        }

        return $loaded;
    }

    /**
     * A prefixed ds:* element appended to its parent: the rule of core.md 6.5 for a built tree.
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
