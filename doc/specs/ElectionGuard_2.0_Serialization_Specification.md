# ElectionGuard 2.0 - Data Serialization Specification - Version 0.0.1 - 2024-07-30

`TBD: bump version`

## What Is This Document and Why Is It Important?

This document specifies in detail how instances of the data structures of the
[ElectionGuard Design Specification](TBD) are to be encoded into bytes.

(In this document we'll just refer to these as 'objects' or 'values', interchangably.)

Specifying this in detail is essential for several reasons:

* ElectionGuard requires that certain data artifacts created during the course of an election be
'published' for observability. These artifacts form a written record by which an election's
results may be independently verified, so they must be reliably and accurately
conveyed across time, storage systems, networks, application software, and other components of
heterogeneous elections systems.

* Together, the Design and Serialization specifications are intended to enable and encourage
the growth of an ecosystem of independently developed, interoperable ElectionGuard implementations.
The availability of complete, consistent, and straightforward-to-implement specifications
are essential.

* Some data artifacts function as cryptographic commitments or intermediate computations from which
the proofs of integrity and correctness of tallies ultimately derive. If these were to become lost,
corrupted, or fail to exchange between systems, the integrity assurances provided by ElectionGuard
could be significantly weakened or delayed.

The serialization format is defined in terms of widely-used industry standards and is intended to
allow use of existing off-the-shelf libraries to the extent practical.

## Conventions Used in This Document

'Design Specification' refers to the ElectionGuard 2.0 Design Specification document.

Unless otherwise qualified, the terms 'data structures', 'instances', 'objects',
'values', etc. are used interchangably.

A 'writer' is any application that intends to produce files which conform to this specification,
a 'Reader' is any application that wishes to read them.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) [[RFC2119]] [[RFC8174]]
when, and only when, they appear in all capitals, as shown here.

## Canonical representation

### File extension

A 'file' is a serialized object representaion intended to be complete enough to be interpreted
independently without need for other context. This term is used to refer to the stand-alone
serialized format, not necessarily a filesystem file.

Filesystem files produced by this specification SHOULD be given the `.eg20` file extension.

### Encoding: UTF-8

File content MUST be valid [UTF-8] with no leading BYTE ORDER MARK (BOM). However, the
`U+FEFF "ZERO WIDTH NO-BREAK SPACE"` character is allowed within string values where it would
otherwise be allowed.

## JSON

Serialized data MUST conform to the [JSON] format as defined in [RFC 8259].

Readers of these serialized values should be able to use any of the widely-available
JSON parsing libraries for their language to interpret the data. However, these parsers
may not provide the information necessary to verify hash integrity.

However, JSON is not a complete specification, so we supply several
additional constraints. A general-purpose JSON serialization library may or may not provide
the features necessary to produce the canonical representation.

### Canonical form

ElectionGuard files have a defined serialized canonical form for hashing purposes.
This form is the subject of this specification.

* The first byte is always an opening `'{'` and the last byte the matching `'}'`.
* Contains absolutely no unnecessary characters, such as formatting spaces, not even
a terminating `CR`, `LF`, or `CRLF` sequence.
* In this respect it may be considered a "binary" file format.
* The content has a well-defined and consistent hash value. It may be hashed in memory as an array
of bytes, or written to a file and hashed using a filesystem utility. Both methods MUST produce
the same hash value.
* Although it MAY be opened and viewed with a plain-text application, it won't be
easy to understand the structure.

In some cases, files are used only to convey information out of the ElectionGuard processing
and not supplied as input to hash computations. Even when the canonical form is not strictly necessary, applications SHOULD provide a way to emit it for external applications that may
wish to perform hashing or comparison.

Non-normative: This document specifies the canonical representation. However, the Reference
implementation in Rust can also emit a "pretty" representation of the object, similar to
running the JSON through a reformatting utility. Although both formats should yield the
same object from the perspective of a general-purpose JSON parser, the serialized object's
hash will obviously not match.

### Property names

The JSON specification states that "The names within an object SHOULD be unique."
This specification requires that they MUST be unique in all cases.

### Missing properties, null, and empty strings

Some object types have optional data fields.

* When an optional field has a `None` value, simply do not emit it as a JSON property at all.
* The [Design Specification][EGDS20] has no fields for which a JSON `null` value would be
appropriate.
* Text-type fields that are optional but require a non-empty string if present MAY use an
empty string in the code implementation to represent the absence of a value. However, they
MUST NOT be emitted as a JSON property in this case.
* The [Design Specification][EGDS20] defines no fields for which an empty string value would
be appropriate.

### Order of properties in objects

Neither the JSON specification nor widespread practice clearly state whether the order of
object names carries semantic meaning. The notes that many parsing libraries do not expose
this order to the Readers of the data structure. However, ElectionGuard objects require a
defined serialized canonical form for hashing purposes, so in this case it definitely
matters.

* Writers of canonical form objects MUST list the object properties in the specified order.
* Readers of canonical form objects MAY ignore the order of object members.

## Text data types

Text data used in ElectionGuard MUST be representable as valid UTF-8.

Text data MUST NOT:

* Contain higher level formats such as HTML or Markdown. The rationale is that
this specification has no provision for communicating the proper format, and displaying text
data as the wrong format could quite possibly be a security vulnerability.
If rich text formatting capabilities are required, it should be carried externally and
referenced to the relevant object's label or index from the election manifest.
Alternatively, a vendor-specific extension could be used.

The JSON [RFC 8259] is a bit ambiguous with respect to Unicode surrogate pair code points
encoded as escaped characters in strings. See [JSON RFC Errata 7603](https://www.rfc-editor.org/errata/eid7603).

* Writers MUST NOT emit JSON strings which if un-encaped would result in a malformed
surrogate pair.
* Readers MUST reject serialized data containing such JSON strings.

Non-normative: The Reference implementation in Rust uses Rust's
[std String](https://doc.rust-lang.org/std/string/struct.String.html) type, which rejects
such malformed sequences automatically.

Text data SHOULD:

* Prefer a single `U+0020 SPACE` as a space character whenever possible.

Text data SHOULD NOT:

* Include tabs or other formatting characters beyond what is necessary to accurately
represent the text.
* Have any leading or trailing whitespace characters.

Text data type properties are, in practice, either "name-type", "description-type", or "labels".

A name type might be expected to appear on a command line or in a spreadsheet
cell, while a description type could reasonably carry multiple paragraphs of text.
Both these types are intended for presentation to users.

On the other hand, "labels" are used to uniquely identify items in the ElectionGuard data
structures and carry aditional requirements. While they may be presented to users, that
is not their primary purpose.

### Name-type text fields

An example of a name-type text field is the `opt_name` field of `GuardianPublicKey` data structure.

In addition to the general requirements applicable to all text data...

Name-type text SHOULD:

* Be human readable and meaningful.
* Be as concise as practical.

Name-type text SHOULD NOT:

* Use `U+00A0 NO-BREAK SPACE` or `U+202F NARROW NO-BREAK SPACE` characters.
* Contain line break or tab characters.
* Contain any leading or trailing whitespace characters.
* Contain contiguous sequences of multiple whitespace characters.

### Description-type text fields

In addition to the general requirements applicable to all text data...

Description-type field text SHOULD:

* Be human readable and meaningful.
* Use a single line break character where a line break is desired.
* Use two consecutive line break characters where a blank line is desired, e.g. to visually separate
paragraphs.
* Include a single trailing line break character on the last line. (This is an exception to
the general prohibition against trailing whitespace characters in consideration for common editor
conventions for plain text files.)

Description-type text SHOULD NOT:

* Assume anything about the font that will ultimately be used for display. I.e., it's probably not
a good idea to try to align columns of text using space or tab characters.

Description-type text MAY:

* Begin lines with a sequence of one or more `U+0009` 'tab' characters.
* Use `U+2007 FIGURE SPACE` characters to line up with digits on nearby lines.
* Use `U+00A0 NO-BREAK SPACE` or `U+202F NARROW NO-BREAK SPACE` as necessary.

### Labels

In addition to the general requirements applicable to all text data...

Labels MUST:

* Identify the item uniquely within its scope.
* Define an equivalence relation that is reflexive and symmetric.
* Be processed with due regard to security considerations.
* Be faithfully preserved by processing software.

Labels MUST NOT:

* Include line break or tab characters.
* Include any leading or trailing whitespace characters.
* Contain contiguous sequences of multiple whitespace characters other than a single `0x20`.
* Contain leading or trailing whitespace characters.

Writers MUST NOT emit serialized data that does not meet "MUST level" requirements.

Readers MUST verify and reject any serialized data that does not meet "MUST level"
requirements.

Labels SHOULD:

* Be human readable. Meaningful is a bonus.
* Be compatible with [NIST SP 1500-20](References) and [1500-100r2](References)

## Numeric and hash values

As a cryptographic system, ElectionGuard is heavily based on numbers, specifically
non-negative integers. In practice these are always far too large to represent as JSON.

### Small integers

Small integers (less than 2^31) are used for things like the number of guardians in a quorum,
or a 1-based index identifying a specific element in a sequence.

They are written as ordinary base-10 integers.

### <a id="Large_integers"></a>Large integers

There are three kinds of cryptographic values used in ElectionGuard:

* Non-negative integers of fixed size corresponding to `q` or `p`.<br/>
  For the standard parameter set, `q`- and `p`-sized values are (respectively):
  * 256 or 4096 bits
  * 64 or 1024 hex digits

These values are written as JSON strings, the content of which MUST match the case-sensitive regex

```regex
    ^[0-9A-F]{N}$
```

where `N` is the number of hex digits specified above.

### Hash values

The `HMAC-SHA-256` function used in ElectionGuard 2.0 produces fixed size values of 256 bits
which are interpreted as [large integers](#Large_integers) of that size and written as described
above.

### Cryptographic values

There are three kinds of cryptographic values used in ElectionGuard:

* Non-negative integers of fixed size corresponding to `q` or `p`.<br/>
  For the standard parameter set, `q`- and `p`-sized values are (respectively):
  * 256 or 4096 bits
  * 64 or 1024 hex digits

* Fixed size `HMAC-SHA-256` values:
  * 256 bits
  * 64 hex digits

These values are written as JSON strings, the content of which MUST match the case-sensitive regex

```regex
    ^[0-9A-F]{N}$
```

where `N` is the number of hex digits specified above.

## Specific Data Structures

### Election Parameters

Non-canonical example:
```json
```

### Hashes

Non-canonical example:
```json
```

### Election Manifest

```json
{
  "label": "General Election - The United Realms of Imaginaria",
  "contests": [
    {
      "label": "For President and Vice President of The United Realms of Imaginaria",
      "selection_limit": 1,
      "options": [
        {
          "label": "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)"
        },
        {
          "label": "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)"
        }
      ]
    },
    {
      "label": "Minister of Arcane Sciences",
      "selection_limit": 1,
      "options": [
        {
          "label": "Élyria Moonshadow\n(Crystâlheärt)"
        },
        {
          "label": "Archímedes Darkstone\n(Ætherwïng)"
        },
        {
          "label": "Seraphína Stormbinder\n(Independent)"
        },
        {
          "label": "Gávrïel Runëbørne\n(Stärsky)"
        }
      ]
    },
    {
      "label": "Minister of Elemental Resources",
      "selection_limit": 1,
      "options": [
        {
          "label": "Tïtus Stormforge\n(Ætherwïng)"
        },
        {
          "label": "Fæ Willowgrove\n(Crystâlheärt)"
        },
        {
          "label": "Tèrra Stonebinder\n(Independent)"
        }
      ]
    },
    {
      "label": "Minister of Dance",
      "selection_limit": 1,
      "options": [
        {
          "label": "Äeliana Sunsong\n(Crystâlheärt)"
        },
        {
          "label": "Thâlia Shadowdance\n(Ætherwïng)"
        },
        {
          "label": "Jasper Moonstep\n(Stärsky)"
        }
      ]
    },
    {
      "label": "Gränd Cøuncil of Arcáne and Technomägical Affairs",
      "selection_limit": 3,
      "options": [
        {
          "label": "Ìgnatius Gearsøul\n(Crystâlheärt)"
        },
        {
          "label": "Èlena Wîndwhisper\n(Technocrat)"
        },
        {
          "label": "Bërnard Månesworn\n(Ætherwïng)"
        },
        {
          "label": "Èmeline Glîmmerwillow\n(Ætherwïng)"
        },
        {
          "label": "Nikólai Thunderstrîde\n(Independent)"
        },
        {
          "label": "Lïliana Fîrestone\n(Pęacemaker)"
        },
        {
          "label": "Émeric Crystálgaze\n(Førestmíst)"
        },
        {
          "label": "Séraphine Lùmenwing\n(Stärsky)"
        },
        {
          "label": "Rãfael Stëamheart\n(Ætherwïng)"
        },
        {
          "label": "Océane Tidecaller\n(Pęacemaker)"
        },
        {
          "label": "Elysêa Shadowbinder\n(Independent)"
        }
      ]
    },
    {
      "label": "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions",
      "selection_limit": 1,
      "options": [
        {
          "label": "For"
        },
        {
          "label": "Against"
        }
      ]
    },
    {
      "label": "Privacy Protection in Techno-Magical Communications Act",
      "selection_limit": 1,
      "options": [
        {
          "label": "Prō"
        },
        {
          "label": "Ĉontrá"
        }
      ]
    },
    {
      "label": "Public Transport Modernization and Enchantment Proposal",
      "selection_limit": 1,
      "options": [
        {
          "label": "Prō"
        },
        {
          "label": "Ĉontrá"
        }
      ]
    },
    {
      "label": "Renewable Ætherwind Infrastructure Initiative",
      "selection_limit": 1,
      "options": [
        {
          "label": "Prō"
        },
        {
          "label": "Ĉontrá"
        }
      ]
    },
    {
      "label": "For Librarian-in-Chief of Smoothstone County",
      "selection_limit": 1,
      "options": [
        {
          "label": "Élise Planetes"
        },
        {
          "label": "Théodoric Inkdrifter"
        }
      ]
    },
    {
      "label": "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained",
      "selection_limit": 1,
      "options": [
        {
          "label": "Retain"
        },
        {
          "label": "Remove"
        }
      ]
    }
  ],
  "ballot_styles": [
    {
      "label": "Smoothstone County Ballot",
      "contests": [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10
      ]
    },
    {
      "label": "Silvërspîre County Ballot",
      "contests": [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        11
      ]
    }
  ]
}

```

### Guardian Secret Key

### Guardian Public Key

### Guardian Public Key Share

### Extended Hashes

### Joint Election Public Key

### Ballot Style

### Pre-voting Data

### Ballot Voter Selections Plaintext

### Ballot Voter Selections Encrypted

## References



|             |     |
| ----------- | --- |
| <a id="refs.RFC2119"></a>\[[RFC2119][RFC2119-html]] | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", [BCP 14](https://datatracker.ietf.org/doc/html/bcp14), [RFC 2119][RFC2119-html], DOI [10.17487/RFC2119](https://doi.org/10.17487/RFC2119), March 1997, <<https://www.rfc-editor.org/info/rfc2119>>. |
| <a id="refs.RFC3629"></a>\[[RFC3629][RFC3629-html]] \[[UTF-8][RFC3629-html]] | Yergeau, F., "UTF-8, a transformation format of ISO 10646", [STD 63](https://datatracker.ietf.org/doc/std63/ "IETF STD 63"), [RFC 3629][RFC3629-html], DOI [10.17487/RFC3629](https://doi.org/10.17487/RFC3629), November 2003, <<https://www.rfc-editor.org/info/rfc3629>>. |
| <a id="refs.RFC8174"></a>\[[RFC8174][RFC8174-html]] | Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", [BCP 14](https://datatracker.ietf.org/doc/html/bcp14 "IETF BCP 14"), [RFC 8174][RFC8174-html], DOI [10.17487/RFC8174](https://doi.org/10.17487/RFC8174), May 2017, <<https://www.rfc-editor.org/info/rfc8174>>. |
| <a id="refs.RFC8259"></a>\[[RFC8259][RFC8259-html]] | Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", [STD 90](https://datatracker.ietf.org/doc/std90/ "IETF STD 90"), [RFC 8259][RFC8259-html], DOI [10.17487/RFC8259](https://doi.org/10.17487/RFC8259), December 2017, <<https://www.rfc-editor.org/info/rfc8259>>. |
| <a id="refs.UNICODE"></a>\[[UNICODE][UNICODE-html]] | The Unicode Consortium, "The Unicode Standard", <<https://www.unicode.org/versions/latest/>>. |
| <a id="refs.EGDS20"></a>\[[EGDS20][EGDS20-pdf]] | Benaloh, J. and M. Naehrig, "ElectionGuard Design Specification Version v2.0.0", <<https://github.com/microsoft/electionguard-rust/tree/main/doc/specs>>. |

[RFC2119-html]: https://datatracker.ietf.org/doc/html/rfc2119 "IETF RFC 2119: Key words for use in RFCs to Indicate Requirement Levels - IETF"
[RFC2119]: #refs.RFC2119 "[RFC 2119] Key words for use in RFCs to Indicate Requirement Levels - IETF"

[RFC3629-html]: https://datatracker.ietf.org/doc/html/rfc3629 "[RFC 3629] UTF-8, a transformation format of ISO 10646 - IETF"
[RFC3629]: #refs.RFC3629 "[RFC 3629] UTF-8, a transformation format of ISO 10646 - IETF"
[UTF-8]: #refs.RFC3629 "[RFC 3629] UTF-8, a transformation format of ISO 10646 - IETF"

[RFC8174-html]: https://datatracker.ietf.org/doc/html/rfc8174 "[RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words - IETF"
[RFC8174]: #refs.RFC8174 "[RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words - IETF"

[RFC8259-html]: https://datatracker.ietf.org/doc/html/rfc8259 "[RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format - IETF"
[RFC8259]: #refs.RFC8259 "[RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format - IETF"
[RFC 8259]: #refs.RFC8259 "[RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format - IETF"
[JSON]: #refs.RFC8259 "[RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format - IETF"

[UNICODE-html]: https://www.unicode.org/versions/latest/ "The Unicode Standard (latest) - The Unicode Consortium"
[UNICODE]: #refs.UNICODE "The Unicode Standard (latest) - The Unicode Consortium"

[EGDS20-pdf]: https://github.com/microsoft/electionguard-rust/tree/main/doc/specs "ElectionGuard Design Specification v2.0 - MSR"
[EGDS20]: #refs.EGDS "ElectionGuard Design Specification v2.0 - MSR"
