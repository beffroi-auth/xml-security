# Security policy

This brick is the parser boundary of an identity provider: what it lets through is what a signature is verified
over, and a flaw here is a flaw in every application that trusts a SAML assertion.

## Reporting

Report privately through [GitHub security advisories](https://github.com/beffroi-php/saml-xml-core/security/advisories/new).
Do not open a public issue, do not discuss it in a pull request.

You will get an acknowledgement within 72 hours, and a fix or a mitigation plan as fast as the severity requires.
Credit is given in the advisory unless you prefer otherwise.

## What is published

Every security fix ships with a GitHub Security Advisory and a CVE requested for it, so that `composer audit`,
Packagist and the advisory databases see it. The existing PHP bricks of this domain fixed canonicalization and
authentication-tag flaws without a published advisory; this package commits to the opposite.

## Scope

Anything in this repository: the loader, the ID index, the canonicalizer, the reading side, the serializer, the
tooling and the CI. The rules the brick enforces are the invariants I-1 to I-16 of `SPECIFICATION.md`, section 4;
a way to defeat one of them with input, without a code change, is a vulnerability. A refusal message that carries
bytes of the input is one too (I-16).

Out of scope: a consumer that calls `Dom\XMLDocument::createFromString()`, `getElementById()` or any other call of
the table of section 8 of the specification, which the brick's PHPStan rules exist to prevent.

## Supported versions

Until the first tagged release, `main` only. From `1.0.0`, the latest minor of the latest major.
