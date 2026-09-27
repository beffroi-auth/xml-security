<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Dom\Element;
use Dom\XMLDocument;
use RuntimeException;

/**
 * What a consumer builds and signs (section 6.2): a SAML-shaped response holding one assertion, every element
 * prefixed, the Issuer first in each, as the tests of the signer and the fixture the signer produced share it.
 */
final class Built
{
    public const string RESPONSE_ID = '_response-b1c2d3';

    public const string ASSERTION_ID = '_assertion-e4f5g6';

    public static function responseWithAssertion(): Document
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
        self::text($xml, self::child($xml, $response, Stack::SAML_ASSERTION, 'saml:Issuer'), 'https://idp.example.org');
        $status = self::child($xml, $response, Stack::SAML_PROTOCOL, 'samlp:Status');
        self::child($xml, $status, Stack::SAML_PROTOCOL, 'samlp:StatusCode')
            ->setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $assertion = self::child($xml, $response, Stack::SAML_ASSERTION, 'saml:Assertion');
        $assertion->setAttribute('ID', self::ASSERTION_ID);
        $assertion->setAttribute('Version', '2.0');
        $assertion->setAttribute('IssueInstant', '2026-09-27T10:00:00Z');
        self::text(
            $xml,
            self::child($xml, $assertion, Stack::SAML_ASSERTION, 'saml:Issuer'),
            'https://idp.example.org',
        );
        $subject = self::child($xml, $assertion, Stack::SAML_ASSERTION, 'saml:Subject');
        $nameId = self::child($xml, $subject, Stack::SAML_ASSERTION, 'saml:NameID');
        $nameId->setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        self::text($xml, $nameId, 'user-0001');
        $conditions = self::child($xml, $assertion, Stack::SAML_ASSERTION, 'saml:Conditions');
        $conditions->setAttribute('NotBefore', '2026-09-27T09:59:00Z');
        $conditions->setAttribute('NotOnOrAfter', '2026-09-27T10:05:00Z');
        $restriction = self::child($xml, $conditions, Stack::SAML_ASSERTION, 'saml:AudienceRestriction');
        self::text(
            $xml,
            self::child($xml, $restriction, Stack::SAML_ASSERTION, 'saml:Audience'),
            'https://sp.example.org',
        );
        $statement = self::child($xml, $assertion, Stack::SAML_ASSERTION, 'saml:AttributeStatement');
        $attribute = self::child($xml, $statement, Stack::SAML_ASSERTION, 'saml:Attribute');
        $attribute->setAttribute('Name', 'mail');
        self::text(
            $xml,
            self::child($xml, $attribute, Stack::SAML_ASSERTION, 'saml:AttributeValue'),
            'user@example.org',
        );

        return $document;
    }

    /**
     * A signed entity descriptor's shape: the Signature will be its first child.
     */
    public static function entityDescriptor(): Document
    {
        $document = new DocumentFactory()->create(new Name(Stack::SAML_METADATA, 'EntityDescriptor'), 'md');
        $root = $document->root();
        $xml = $root->ownerDocument;
        if (! $xml instanceof XMLDocument) {
            throw new RuntimeException('The root has its document.');
        }
        $root->setAttribute('ID', '_entity-h7i8j9');
        $root->setAttribute('entityID', 'https://idp.example.org');
        $descriptor = self::child($xml, $root, Stack::SAML_METADATA, 'md:IDPSSODescriptor');
        $descriptor->setAttribute('protocolSupportEnumeration', Stack::SAML_PROTOCOL);
        $service = self::child($xml, $descriptor, Stack::SAML_METADATA, 'md:SingleSignOnService');
        $service->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
        $service->setAttribute('Location', 'https://idp.example.org/sso');

        return $document;
    }

    private static function child(XMLDocument $xml, Element $parent, string $namespace, string $qualified): Element
    {
        $child = $xml->createElementNS($namespace, $qualified);
        $parent->appendChild($child);

        return $child;
    }

    private static function text(XMLDocument $xml, Element $element, string $text): void
    {
        $element->appendChild($xml->createTextNode($text));
    }
}
