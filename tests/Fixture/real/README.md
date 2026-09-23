# Real documents (specification, section 9.4)

Public documents only, captured once, byte for byte, dated in the file name. Nothing here is fabricated, and nothing
here is anonymised unless said so.

| File | Origin | Notes |
|---|---|---|
| `entra-common-federation-metadata-2026-09-23.xml` | `https://login.microsoftonline.com/common/FederationMetadata/2007-06/FederationMetadata.xml`, captured on 23 September 2026 | The common (multi-tenant) federation metadata of Microsoft Entra ID: public, no tenant in it, the `{tenantid}` placeholder is literal. 31 752 bytes, starting with a UTF-8 byte order mark (`EF BB BF`), encoding declared `utf-8`, one `ID`, 166 elements, depth 6, 49 namespace declarations. Kept as captured, byte order mark included. |

Missing, to be captured when the sub-spike has them: an Entra SAML response and assertion from a test tenant, ADFS
federation metadata and a response from a test farm, SimpleSAMLphp IdP and SP metadata, an AuthnRequest, a response
with a signed assertion and a LogoutRequest from the container the spike runs, Okta IdP metadata from a developer
tenant.
