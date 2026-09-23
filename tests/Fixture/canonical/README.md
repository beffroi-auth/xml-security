# Canonicalization vectors (specification, section 9.1)

Every `.xml` file is an input; the `.c14n` files next to it are the expected canonical forms, one per method, and end
without a line feed. Nothing here was written from memory: each vector is transcribed from the recommendation, each
derived fixture names its source and the change made, and every expected form was checked against libxml before
being committed (the generator ran outside the repository, the one place XPath is used, for the node-set forms of the
enveloped cases under `../behaviour/`).

## Canonical XML Version 1.0, W3C Recommendation, 15 March 2001, section 3

Source: https://www.w3.org/TR/2001/REC-xml-c14n-20010315, the rendered examples (`<code>` blocks: a `<br/>` is a
line feed, a `&nbsp;` a space, an entity its character). Cross-checked against libxml2's copy of the examples
(`test/c14n/`), which comes from an earlier draft (`http://www.uvic.ca` where the recommendation says
`http://example.org`).

| File | Source | Change made |
|---|---|---|
| `c14n-3.1-derived-a-outside-nodes.xml` | §3.1 PIs, Comments, and Outside of Document Element | the line `<!DOCTYPE doc SYSTEM "doc.dtd">` and the blank line after it removed; the external subset contributed nothing. The processing instructions and comments outside `doc` stay where they are: the apex of section 5.4 is an element, and nothing outside it is rendered, so the expected forms are the `doc` line of the recommendation's forms |
| `c14n-3.1-derived-b-nodes-inside-doc.xml` | §3.1 | the declaration removed, and the processing instructions and comments outside `doc` moved inside it, in their order; the expected forms are the recommendation's lines rendered inside `doc`, which puts no line feed between them |
| `c14n-3.2-whitespace-in-content.xml` | §3.2 Whitespace in Document Content | none |
| `c14n-3.3-derived-start-and-end-tags.xml` | §3.3 Start and End Tags | the line `<!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>` removed, and `attr="default"`, which the DTD gave to `e9`, removed from the expected form. The rendered form carries a space before every line break, an artefact of the HTML source that the algorithm cannot produce and that libxml2's copy does not have: dropped |
| `c14n-3.4-derived-character-references.xml` | §3.4 Character Modifications and Character References | the internal subset removed, and the `normNames` and `normId` elements removed from the input and the expected form: their attribute normalisation depended on the `NMTOKENS` and `ID` types the DTD declared |
| `c14n-3.6-derived-utf-8.xml` | §3.6 UTF-8 Encoding | the declared encoding `ISO-8859-1` changed to `UTF-8`; the expected form holds the two bytes `C2 A9` the note under the example describes, not the placeholder `#xC2#xA9` |

The originals of §3.1, §3.3, §3.4, §3.5 and §3.7 carry a document type declaration and the original of §3.6 declares
`ISO-8859-1`: they sit under `../hostile/` as `c14n-<section>-original-*-refused.xml`. §3.5 (entity references) and
§3.7 (document subsets, an XPath node set) are refused by design and have no derived fixture.

## Exclusive XML Canonicalization Version 1.0, W3C Recommendation, 18 July 2002

Source: https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/. The recommendation prints its forms "except for line
wrapping to fit this document": the wrapped start tags are written on one line here, as the algorithm renders them.

| File | Source | Change made |
|---|---|---|
| `exc-c14n-2.1-elem1-in-pdu.xml` | §2.1 A Simple Example, `n1:elem1` enveloped in `n0:pdu` | the three leading spaces of the first line of the `<pre>` block dropped; the apex is `n1:elem1` |
| `exc-c14n-2.2-elem2-in-local.xml` | §2.2 General Problems with re-Enveloping, the `n0:local` document | the same; the apex is `n1:elem2` |
| `exc-c14n-2.2-derived-elem2-re-enveloped.xml` | §2.2, the `n2:pdu` document | `xml:space="retain"` changed to `xml:space="preserve"`: libxml reports the value `retain` as a level-1 diagnostic, and I-3 refuses it |

## The measured cases (specification, section 13)

`measured-apex-under-ancestors.xml`: an apex `s:a` under a root declaring a default namespace, `s`, `x`, an unused
prefix and `xml:lang`. Rendered inclusive (everything in scope, the inherited `xml:lang` included), exclusive (the
namespaces visibly utilised only), exclusive with `PrefixList="unused"`, and exclusive with `PrefixList="#default"`.
