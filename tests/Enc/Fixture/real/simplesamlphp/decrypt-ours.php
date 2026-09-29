<?php
declare(strict_types=1);
require '/app/vendor/autoload.php';
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Message;
ContainerSingleton::setContainer(new MockContainer());
$key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'private']);
$key->loadKey(file_get_contents('/fixtures/keys/test-signing-key.pem'));
foreach ([
    'behaviour/encrypted-by-the-encryptor-aes256-gcm.xml' => 'ours, aes256-gcm',
    'behaviour/encrypted-by-the-encryptor-aes128-gcm.xml' => 'ours, aes128-gcm',
    'vectors/response-encrypted-assertion-aes256-gcm.xml' => 'xmlsec1, aes256-gcm',
    'vectors/response-encrypted-assertion-rsa-oaep-sha256.xml' => 'xmlsec1, rsa-oaep sha256',
    'hostile/tag-truncated-refused.xml' => 'the tag truncated',
] as $file => $label) {
    $dom = new DOMDocument(); $dom->loadXML(file_get_contents('/fixtures/' . $file));
    try {
        $response = Message::fromXML($dom->documentElement);
        $assertion = $response->getAssertions()[0]->getAssertion($key);
        printf("%-28s decrypted: id %s, issuer %s, %d attribute(s)\n", $label, $assertion->getId(), $assertion->getIssuer()->getValue(), count($assertion->getAttributes()));
    } catch (Throwable $e) {
        printf("%-28s %s: %s\n", $label, $e::class, substr($e->getMessage(), 0, 90));
    }
}
