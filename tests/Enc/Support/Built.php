<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Dom\Element;
use Dom\XMLDocument;
use RuntimeException;

/**
 * What a consumer builds and encrypts (section 6.2): a SAML-shaped response holding one assertion, every element
 * prefixed, the Issuer first in each; the assertion is what the tests of the encryptor hand it.
 */
final class Built
{
    public const string RESPONSE_ID = '_response-b1c2d3';

    public const string ASSERTION_ID = '_assertion-e4f5g6';

    public const string COMMENT = ' a comment the encryptor keeps ';

    public static function responseWithAssertion(): Document
    {
        return self::response(null);
    }

    /**
     * The same, a comment inside the NameID: what the exclusive canonical form with comments keeps (E-9).
     */
    public static function responseWithCommentedAssertion(): Document
    {
        return self::response(self::COMMENT);
    }

    /**
     * The assertion of a built response, the element a consumer encrypts: found among the children, since a built
     * document has no ID index before it is loaded (core.md section 6.2).
     */
    public static function assertionOf(Document $document): Element
    {
        return Children::one($document->root(), new Name(Stack::SAML_ASSERTION, 'Assertion'));
    }

    private static function response(?string $comment): Document
    {
        $document = new DocumentFactory()->create(new Name(Stack::SAML_PROTOCOL, 'Response'), 'samlp');
        $response = $document->root();
        $xml = $response->ownerDocument;
        if (! $xml instanceof XMLDocument) {
            throw new RuntimeException('The root has its document.');
        }
        $response->setAttribute('ID', self::RESPONSE_ID);
        $response->setAttribute('Version', '2.0');
        $response->setAttribute('IssueInstant', '2026-09-27T10:00:00Z');
        $response->setAttribute('Destination', 'https://sp.example.org/acs');
        self::text($xml, self::child($xml, $response, 'saml:Issuer'), 'https://idp.example.org');
        $status = self::child($xml, $response, 'samlp:Status', Stack::SAML_PROTOCOL);
        self::child($xml, $status, 'samlp:StatusCode', Stack::SAML_PROTOCOL)
            ->setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $assertion = self::child($xml, $response, 'saml:Assertion');
        $assertion->setAttribute('ID', self::ASSERTION_ID);
        $assertion->setAttribute('Version', '2.0');
        $assertion->setAttribute('IssueInstant', '2026-09-27T10:00:00Z');
        self::text($xml, self::child($xml, $assertion, 'saml:Issuer'), 'https://idp.example.org');
        $subject = self::child($xml, $assertion, 'saml:Subject');
        $nameId = self::child($xml, $subject, 'saml:NameID');
        $nameId->setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        self::text($xml, $nameId, 'user-');
        if ($comment !== null) {
            $nameId->appendChild($xml->createComment($comment));
        }
        self::text($xml, $nameId, '0001');
        $conditions = self::child($xml, $assertion, 'saml:Conditions');
        $conditions->setAttribute('NotBefore', '2026-09-27T09:59:00Z');
        $conditions->setAttribute('NotOnOrAfter', '2026-09-27T10:05:00Z');
        $restriction = self::child($xml, $conditions, 'saml:AudienceRestriction');
        self::text($xml, self::child($xml, $restriction, 'saml:Audience'), 'https://sp.example.org');
        $statement = self::child($xml, $assertion, 'saml:AttributeStatement');
        $attribute = self::child($xml, $statement, 'saml:Attribute');
        $attribute->setAttribute('Name', 'mail');
        self::text($xml, self::child($xml, $attribute, 'saml:AttributeValue'), 'user@example.org');

        return $document;
    }

    private static function child(
        XMLDocument $xml,
        Element $parent,
        string $qualified,
        string $namespace = Stack::SAML_ASSERTION,
    ): Element {
        $child = $xml->createElementNS($namespace, $qualified);
        $parent->appendChild($child);

        return $child;
    }

    private static function text(XMLDocument $xml, Element $element, string $text): void
    {
        $element->appendChild($xml->createTextNode($text));
    }
}
