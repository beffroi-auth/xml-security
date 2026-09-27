<?php
declare(strict_types=1);
require '/app/vendor/autoload.php';
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Message;
ContainerSingleton::setContainer(new MockContainer());
$cert = file_get_contents('/fixtures/keys/test-signing-certificate.pem');
function publicKey(string $cert): XMLSecurityKey { $k = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']); $k->loadKey($cert, false, true); return $k; }
foreach (['behaviour/signed-by-the-signer-assertion-rsa-sha256.xml' => 'assertion', 'behaviour/signed-by-the-signer-both-rsa-sha256.xml' => 'both', 'vectors/response-assertion-rsa-sha256.xml' => 'xmlsec1 assertion'] as $file => $label) {
    $dom = new DOMDocument(); $dom->loadXML(file_get_contents('/fixtures/' . $file));
    $response = Message::fromXML($dom->documentElement);
    $assertions = $response->getAssertions();
    $assertionOk = $assertions[0]->validate(publicKey($cert));
    $responseOk = $label === 'both' ? $response->validate(publicKey($cert)) : 'n/a';
    printf("%-20s assertion: %s   response: %s\n", $label, var_export($assertionOk, true), var_export($responseOk, true));
}
// a tampered one must fail
$dom = new DOMDocument(); $dom->loadXML(file_get_contents('/fixtures/hostile/signed-element-altered-refused.xml'));
try { $r = Message::fromXML($dom->documentElement); printf("%-20s assertion: %s\n", 'tampered (xmlsec1)', var_export($r->getAssertions()[0]->validate(publicKey($cert)), true)); } catch (Throwable $e) { printf("%-20s %s: %s\n", 'tampered (xmlsec1)', $e::class, $e->getMessage()); }
