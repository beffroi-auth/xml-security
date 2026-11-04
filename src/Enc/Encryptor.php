<?php

declare(strict_types=1);

namespace Beffroi\Xml\Enc;

use function base64_encode;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Internal\Registry;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\Internal\Names;
use Beffroi\Xml\Enc\Internal\Pem;
use function chunk_split;
use Dom\Element;
use Dom\XMLDocument;
use function implode;
use InvalidArgumentException;
use function openssl_encrypt;
use const OPENSSL_RAW_DATA;
use function random_bytes;
use function rtrim;
use SensitiveParameter;

/**
 * Section 6.2, E-8, E-9, E-10
 */
final readonly class Encryptor
{
    public function __construct(
        private Loader $loader,
        private Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {
    }

    /**
     * Returns the xenc:EncryptedData unattached: the consumer places it and removes the plaintext element itself.
     *
     * @throws InvalidKey when $certificatePem is not exactly one certificate
     * @throws RefusedXml what the loader refuses of the plaintext
     * @throws AlgorithmUnavailable
     * @throws InvalidArgumentException when $element is not connected to its document, or an element of its
     *                                  subtree without a prefix has no declaration in scope
     * @throws EncryptionFailed
     * @throws ForeignNode
     */
    public function encrypt(
        Element $element,
        PeerKey $peer,
        ContentAlgorithm $algorithm = ContentAlgorithm::Aes256Gcm,
        KeyTransport $transport = new KeyTransport(OaepHash::Sha1),
        #[SensitiveParameter]
        ?string $certificatePem = null,
    ): Element {
        if (! $transport->hash->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot wrap under a hash other than SHA-1: the RSA functions take no digest before PHP 8.5 (section 13).');
        }
        $certificate = $certificatePem === null
            ? null
            : base64_encode(
                Pem::block(
                    $certificatePem,
                    'CERTIFICATE',
                ) ?? throw new InvalidKey('The certificate is one PEM block of type CERTIFICATE and nothing else (E-14).'),
            );
        $plaintext = $this->canonicalizer->canonicalize(
            $element,
            CanonicalizationMethod::ExclusiveWithComments,
            $this->prefixesInScope($element),
        )->bytes;
        // What no parser accepts, a namespace name C14N() wrote raw, is refused here and not by the peer.
        $this->loader->load($plaintext);
        $sessionKey = random_bytes($algorithm->keyBytes());
        $iv = random_bytes(ContentAlgorithm::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            $algorithm->cipher(),
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            ContentAlgorithm::TAG_BYTES,
        );
        if ($ciphertext === false) {
            throw new EncryptionFailed('OpenSSL could not encrypt the element (section 6.2).');
        }
        $wrapped = $peer->wrap($sessionKey, $transport->hash);

        $xml = Registry::xmlOf(Document::owning($element));
        $data = $xml->createElementNS(Names::XMLENC, 'xenc:EncryptedData');
        $data->setAttribute('Type', Names::TYPE_ELEMENT);
        $this->child($xml, $data, Names::XMLENC, 'xenc:EncryptionMethod')->setAttribute('Algorithm', $algorithm->value);
        $key = $this->child(
            $xml,
            $this->child($xml, $data, Names::DSIG, 'ds:KeyInfo'),
            Names::XMLENC,
            'xenc:EncryptedKey',
        );
        $method = $this->child($xml, $key, Names::XMLENC, 'xenc:EncryptionMethod');
        $method->setAttribute('Algorithm', $transport->uri());
        if ($transport->hash !== OaepHash::Sha1) {
            $this->child($xml, $method, Names::DSIG, 'ds:DigestMethod')->setAttribute(
                'Algorithm',
                $transport->hash->value,
            );
            $this->child($xml, $method, Names::XMLENC11, 'xenc11:MGF')->setAttribute(
                'Algorithm',
                $transport->hash->mgfUri(),
            );
        }
        if ($certificate !== null) {
            $x509 = $this->child(
                $xml,
                $this->child($xml, $key, Names::DSIG, 'ds:KeyInfo'),
                Names::DSIG,
                'ds:X509Data',
            );
            $this->child(
                $xml,
                $x509,
                Names::DSIG,
                'ds:X509Certificate',
            )->appendChild($xml->createTextNode($certificate));
        }
        $this->cipherData($xml, $key, $wrapped);
        $this->cipherData($xml, $data, $iv . $ciphertext . $tag);

        return $data;
    }

    /**
     * Every prefix in scope, #default included: exclusive C14N alone omits declarations a QName value needs (E-9).
     */
    private function prefixesInScope(Element $element): InclusiveNamespaces
    {
        $prefixes = [];
        foreach ($element->getInScopeNamespaces() as $namespace) {
            $prefixes[] = $namespace->prefix ?? '#default';
        }

        return InclusiveNamespaces::fromPrefixList(implode(' ', $prefixes));
    }

    /**
     * core.md section 6.5
     */
    private function child(XMLDocument $xml, Element $parent, string $namespace, string $qualified): Element
    {
        $child = $xml->createElementNS($namespace, $qualified);
        $parent->appendChild($child);

        return $child;
    }

    /**
     * Base64 in lines of 76 characters, as the interoperability targets write it (section 6.2 step 6).
     */
    private function cipherData(XMLDocument $xml, Element $parent, string $bytes): void
    {
        $this->child(
            $xml,
            $this->child($xml, $parent, Names::XMLENC, 'xenc:CipherData'),
            Names::XMLENC,
            'xenc:CipherValue',
        )->appendChild($xml->createTextNode(rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n")));
    }
}
