<?php

declare(strict_types=1);

namespace Beffroi\Xml\Dsig;

use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\Internal\Names;
use function constant;
use Dom\Element;
use function hash_equals;
use function openssl_verify;

/**
 * Verification in the order of section 6.1: the Signature as the direct child of the claimed element (D-1), the
 * reading model and its whitelists (D-3, D-4, D-5, D-9), SignedInfo canonicalized and its signature verified
 * against the trusted keys (D-7, D-8), and only then the reference resolved by identity (D-2) and the digest of
 * the element computed with the Signature excluded (D-6). The result is the reload of the bytes that were hashed
 * (D-10). The one openssl_verify() call of the namespace lives here (D-15).
 */
final readonly class Verifier
{
    /**
     * @param Loader $loader the consumer's, with its ID attributes and limits: it re-parses the hashed bytes (D-10)
     */
    public function __construct(
        private Loader $loader,
        private Canonicalizer $canonicalizer = new Canonicalizer(),
    ) {
    }

    /**
     * @param Element $signed the element the consumer claims is signed: the Signature is its direct child (D-1)
     *
     * @throws Exception\SignatureRefused one of its subclasses, naming the rule (D-13)
     * @throws ForeignNode when $signed is not of a document of the brick
     * @throws RefusedXml what Core refuses of the Signature child (D-1) and of the reload (D-10)
     */
    public function verify(Element $signed, VerificationKeys $keys): Verified
    {
        $document = Document::owning($signed);
        $element = Children::one($signed, Names::dsig('Signature'));
        $signature = Signature::of($element);
        $algorithm = $signature->signedInfo->signatureMethod;
        if (! $algorithm->isAvailable()) {
            throw new AlgorithmUnavailable('This build cannot verify RSASSA-PSS: OPENSSL_PKCS1_PSS_PADDING is undefined before PHP 8.5 (section 13).');
        }
        $signedInfo = $this->canonicalizer->canonicalize(
            $signature->signedInfo->element,
            $signature->signedInfo->canonicalizationMethod,
            $signature->signedInfo->inclusiveNamespaces,
        );
        $key = $this->keyThatVerifies($signedInfo->bytes, $signature->signatureValue, $algorithm, $keys);
        $reference = $signature->signedInfo->reference;
        if (! $document->hasId($reference->id) || $document->elementById($reference->id) !== $signed) {
            throw new WrongReference('The reference does not name the claimed element (D-2).');
        }
        // always without comments: the node-set a same-document reference identifies omits them (XML Signature 1.1
        // §4.4.3.3), whatever the transform says (section 6.1 step 8)
        $canonical = $this->canonicalizer->canonicalize(
            $signed,
            CanonicalizationMethod::Exclusive,
            $reference->inclusiveNamespaces,
            [$element],
        );
        if (! hash_equals($reference->digestValue, $reference->digestMethod->hash($canonical->bytes))) {
            throw new DigestMismatch('The claimed element is not what was signed (D-8).');
        }

        return new Verified($this->loader->load($canonical->bytes), $canonical, $algorithm, $key);
    }

    /**
     * The first trusted key under which openssl_verify() returns 1 (D-8); 0, -1 and false on every key is a
     * mismatch, and nothing about which key came close is kept (D-13).
     *
     * @throws SignatureMismatch
     */
    private function keyThatVerifies(
        string $bytes,
        string $signatureValue,
        SignatureAlgorithm $algorithm,
        VerificationKeys $keys,
    ): VerificationKey {
        $digest = $algorithm->digest()->opensslAlgorithm();
        // the padding parameter exists on PHP 8.5 only, and isAvailable() was checked: a PSS scheme passes it,
        // a PKCS#1 v1.5 scheme leaves the default in place, whatever the build
        $padding = $algorithm->isPss() ? [constant('OPENSSL_PKCS1_PSS_PADDING')] : [];
        foreach ($keys->keys as $key) {
            if (openssl_verify($bytes, $signatureValue, $key->handle(), $digest, ...$padding) === 1) {
                return $key;
            }
        }

        throw new SignatureMismatch('No trusted key verifies the signature over SignedInfo (D-7, D-8).');
    }
}
