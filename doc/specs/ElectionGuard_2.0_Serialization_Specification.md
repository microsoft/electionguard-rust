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

### JSON Schema validation

[JSON Schema][JSONSCHEMA] is used to validate the files.

Schema files are provided in the `ElectionGuard_2.0_jsonschema` subdirectory.

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
and not supplied as input to hash computations. Even when the canonical form is not strictly
necessary, applications SHOULD provide a way to emit it for external applications that may
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

The JSON [RFC 8259] is somewhat ambiguous with respect to Unicode surrogate pair code points
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

### Name-type text fields

An example of a name-type text field is the `opt_name` field of `GuardianPublicKey` data structure.

In addition to the general requirements applicable to all text data...

Name-type text SHOULD:

* Be human readable and meaningful.
* Be as concise as practical.

Name-type text SHOULD NOT:

* Use `U+00A0 NO-BREAK SPACE` or `U+202F NARROW NO-BREAK SPACE` characters.
* Contain any leading or trailing whitespace characters.
* Contain contiguous sequences of multiple whitespace characters.

Name-type text MAY:

* Contain line break characters.

### Labels

In addition to the general requirements applicable to all text data...

Labels MUST:

* Be human readable and meaningful.
* Be as concise as practical.
* Identify the item uniquely within its scope.
* Define an equivalence relation that is reflexive and symmetric.
* Be processed with due regard to security considerations.
* Be faithfully preserved by processing software.

Labels MUST NOT:

* Use `U+00A0 NO-BREAK SPACE` or `U+202F NARROW NO-BREAK SPACE` characters.
* Contain any leading or trailing whitespace characters.
* Contain contiguous sequences of multiple whitespace characters.

Labels text MAY:

* Contain line break characters.

Writers MUST NOT emit serialized data that does not meet "MUST level" requirements.

Readers MUST verify and reject any serialized data that does not meet "MUST level"
requirements.

Labels SHOULD:

* Be human readable. Meaningful is a bonus.
* Be compatible with [NIST SP 1500-20](References) and [1500-100r2](References)

## Numeric and hash values

As a cryptographic system, ElectionGuard is heavily based on numbers, specifically
non-negative integers. In practice, the cryptographic values are far too large to
represent directly in JSON. But basic JSON integers are used to represent real-world
quantities.

### <a id="Small_integers"></a>Small integers

Small integers (less than 2^31) are used for things like the number of guardians in a
quorum, or a 1-based index identifying a specific element in a sequence.

They are written as ordinary JSON numbers (base-10).

### Medium integers

Medium integers (less than 2^53) are used for things like vote totals.

This upper limit is chosen to be compatible with scripting language interpreters
that internally represent integers as double-precision floating point values.

Like small integers, they are written as ordinary JSON numbers (base-10).

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

The `HMAC-SHA-256` function used in ElectionGuard 2.0 produces fixed size of 32 bytes

which are interpreted (using big-endian) as [large integers](#Large_integers) of that size and
written as described above. See the [Design Specification][EGDS20] sections 5.1 and 5.4 for more information.

## Election Parameters

The public `election_parameters.json` file is validated by the
[`election_parameters.json`](./ElectionGuard_2.0_jsonschema/election_parameters.json) schema file.

Example in non-canonical form:

```json
{
  "fixed_parameters": {
      "ElectionGuard_Design_Specification_version": {
        "number": [
          2,
          0
        ]
    },
    "generation_parameters": {
      "q_bits_total": 256,
      "p_bits_total": 4096,
      "p_bits_msb_fixed_1": 256,
      "p_middle_bits_source": "ln_2",
      "p_bits_lsb_fixed_1": 256
    },
    "field": {
      "q": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"
    },
    "group": {
      "p": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB17217F7D1CF79ABC9E3B39803F2F6AF40F343267298B62D8A0D175B8BAAFA2BE7B876206DEBAC98559552FB4AFA1B10ED2EAE35C138214427573B291169B8253E96CA16224AE8C51ACBDA11317C387EB9EA9BC3B136603B256FA0EC7657F74B72CE87B19D6548CAF5DFA6BD38303248655FA1872F20E3A2DA2D97C50F3FD5C607F4CA11FB5BFB90610D30F88FE551A2EE569D6DFC1EFA157D2E23DE1400B39617460775DB8990E5C943E732B479CD33CCCC4E659393514C4C1A1E0BD1D6095D25669B333564A3376A9C7F8A5E148E82074DB6015CFE7AA30C480A5417350D2C955D5179B1E17B9DAE313CDB6C606CB1078F735D1B2DB31B5F50B5185064C18B4D162DB3B365853D7598A1951AE273EE5570B6C68F96983496D4E6D330AF889B44A02554731CDC8EA17293D1228A4EF98D6F5177FBCF0755268A5C1F9538B98261AFFD446B1CA3CF5E9222B88C66D3C5422183EDC99421090BBB16FAF3D949F236E02B20CEE886B905C128D53D0BD2F9621363196AF503020060E49908391A0C57339BA2BEBA7D052AC5B61CC4E9207CEF2F0CE2D7373958D762265890445744FB5F2DA4B751005892D356890DEFE9CAD9B9D4B713E06162A2D8FDD0DF2FD608FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "g": "36036FED214F3B50DC566D3A312FE4131FEE1C2BCE6D02EA39B477AC05F7F885F38CFE77A7E45ACF4029114C4D7A9BFE058BF2F995D2479D3DDA618FFD910D3C4236AB2CFDD783A5016F7465CF59BBF45D24A22F130F2D04FE93B2D58BB9C1D1D27FC9A17D2AF49A779F3FFBDCA22900C14202EE6C99616034BE35CBCDD3E7BB7996ADFE534B63CCA41E21FF5DC778EBB1B86C53BFBE99987D7AEA0756237FB40922139F90A62F2AA8D9AD34DFF799E33C857A6468D001ACF3B681DB87DC4242755E2AC5A5027DB81984F033C4D178371F273DBB4FCEA1E628C23E52759BC7765728035CEA26B44C49A65666889820A45C33DD37EA4A1D00CB62305CD541BE1E8A92685A07012B1A20A746C3591A2DB3815000D2AACCFE43DC49E828C1ED7387466AFD8E4BF1935593B2A442EEC271C50AD39F733797A1EA11802A2557916534662A6B7E9A9E449A24C8CFF809E79A4D806EB681119330E6C57985E39B200B4893639FDFDEA49F76AD1ACD997EBA13657541E79EC57437E504EDA9DD011061516C643FB30D6D58AFCCD28B73FEDA29EC12B01A5EB86399A593A9D5F450DE39CB92962C5EC6925348DB54D128FD99C14B457F883EC20112A75A6A0581D3D80A3B4EF09EC86F9552FFDA1653F133AA2534983A6F31B0EE4697935A6B1EA2F75B85E7EBA151BA486094D68722B054633FEC51CA3F29B31E77E317B178B6B9D8AE0F",
      "q": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"
    }
  },
  "varying_parameters": {
    "n": 5,
    "k": 3,
    "info": "The United Realms of Imaginaria General Election 2024",
    "date": "2024-08-05",
    "ballot_chaining": "Prohibited"
  }
}
```

## Hashes

The public `hashes.json` file is validated by the
[`hashes.json`](./ElectionGuard_2.0_jsonschema/hashes.json) schema file.

Example in non-canonical form:

```json
{
  "h_p": "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296",
  "h_m": "7CAAAD91B51C5EF9E406EBFACA47AACB5C9BDA82D553719A0279076ED1E284C9",
  "h_b": "722346503D070901DEC5EF88BA06135FDCB0BC10BB4F918EC45F4EF57C481896"
}
```

## Election Manifest

The public `election_manifest_canonical.bin` file is validated by the
[`election_manifest.json`](./ElectionGuard_2.0_jsonschema/election_manifest.json) schema file.

### Selection Limits

Selection limits define the number of "votes" a voter may cast for each option in a specific
contest. In the most traditional type of election contest, each voter may cast exactly one
vote. But there is a variety of other contest types in common use, and ElectionGuard can
support many of them. For example, an election may be held to fill two or more seats on some
Council or Board. If these seats are to be truly indistinguishable, they cannot have separate
contests because these contests would have to have the same set of candidates, which would
introduce the potential for conflicting outcomes, etc. So voting systems must support the
ability to select multiple candidates in a single contest.

The *default* selection limit, to be used when not stated in the manifest:

* Is `1` for both contests and contest options.

Writers of canonical form objects MUST NOT emit the `selection_limit` property if it
has this value. It MUST be omitted whenever possible.

The *stated* selection limit in an election manifest:

table

|             |     |
| ----------- | --- |
| Contest | MUST be either a [small integer](#Small_integers) or the string `"NO_LIMIT"`. |
| Option  | MUST be either a [small integer](#Small_integers) or the string `"CONTEST_LIMIT"` |

However, if the contest specifies `"NO_LIMIT"` all its options MUST specify (or default to)
integer selection limits.

* Contest - MUST be either a [small integer](#Small_integers) or the string `"NO_LIMIT"`.

* Contest option - MUST be either a [small integer](#Small_integers) or, if its containing contest
specifies an integer selection limit, the string `"CONTEST_LIMIT"`. This implies that for every
option, at least one of itself or its containing contest MUST specify (or default to) an integer
limit.

The *effective* selection limit, which is always a small integer, is:

* Contest - The same as its stated (or defaulted-to) contest selection limit, unless all its
options have integer-valued selection limits, in which case it is the smaller of its limit and the
sum of its options' selection limits.

* Contest option - The same as its stated (or defaulted-to) contest selection limit, unless
its containing contest has an integer-valued selection limit, in which case the option limit
is the smaller of its limit and the contest's selection limit.
* The `selection_limit` of a contest MUST be either a [small integer](#Small_integers) or
the string `"NO_LIMIT"`.

Note that in figuring a contest's effective selection limit from its options, or an option's
effective selection limit from its containing contest, it does not actually matter whether
the stated or effective selection limits are employed.

### Example

Example in non-canonical form:

```json
{
  "label": "General Election - The United Realms of Imaginaria",
  "contests": [
    {
      "label": "For President and Vice President of The United Realms of Imaginaria",
      "options": [
        {
          "label": "Thündéroak, Vâlêriana D.\nËverbright, Ålistair R. Jr.\n(Ætherwïng)"
        }, {
          "label": "Stârførge, Cássánder A.\nMøonfire, Célestïa L.\n(Crystâlheärt)"
        }
      ]
    },
    {
      "label": "Minister of Arcane Sciences",
      "options": [
        {
          "label": "Élyria Moonshadow\n(Crystâlheärt)"
        }, {
          "label": "Archímedes Darkstone\n(Ætherwïng)"
        }, {
          "label": "Seraphína Stormbinder\n(Independent)"
        },
        {
          "label": "Gávrïel Runëbørne\n(Stärsky)"
        }
      ]
    }, {
      "label": "Minister of Elemental Resources",
      "options": [
        {
          "label": "Tïtus Stormforge\n(Ætherwïng)"
        }, {
          "label": "Fæ Willowgrove\n(Crystâlheärt)"
        }, {
          "label": "Tèrra Stonebinder\n(Independent)"
        }
      ]
    }, {
      "label": "Minister of Dance",
      "options": [
        {
          "label": "Äeliana Sunsong\n(Crystâlheärt)"
        }, {
          "label": "Thâlia Shadowdance\n(Ætherwïng)"
        }, {
          "label": "Jasper Moonstep\n(Stärsky)"
        }
      ]
    }, {
      "label": "Gränd Cøuncil of Arcáne and Technomägical Affairs",
      "selection_limit": 3,
      "options": [
        {
          "label": "Ìgnatius Gearsøul\n(Crystâlheärt)"
        }, {
          "label": "Èlena Wîndwhisper\n(Technocrat)",
          "selection_limit": "CONTEST_LIMIT"
        }, {
          "label": "Bërnard Månesworn\n(Ætherwïng)",
          "selection_limit": 8
        }, {
          "label": "Émeric Crystálgaze\n(Førestmíst)",
          "selection_limit": 4
        }
      ]
    }, {
      "label": "Proposed Amendment No. 1\nEqual Representation for Technological and Magical Profeſsions",
      "options": [
        {
          "label": "For",
          "selection_limit": "CONTEST_LIMIT"
        }, {
          "label": "Against"
        }
      ]
    }, {
      "label": "Privacy Protection in Techno-Magical Communications Act",
      "options": [
        {
          "label": "Prō"
        }, {
          "label": "Ĉontrá"
        }
      ]
    }, {
      "label": "Public Transport Modernization and Enchantment Proposal",
      "options": [
        {
          "label": "Prō"
        }, {
          "label": "Ĉontrá"
        }
      ]
    }, {
      "label": "Renewable Ætherwind Infrastructure Initiative",
      "options": [
        {
          "label": "Prō"
        }, {
          "label": "Ĉontrá"
        }
      ]
    }, {
      "label": "For Librarian-in-Chief of Smoothstone County",
      "selection_limit": 2147483647,
      "options": [
        {
          "label": "Élise Planetes",
          "selection_limit": "CONTEST_LIMIT"
        }, {
          "label": "Théodoric Inkdrifter",
          "selection_limit": 2147483647
        }
      ]
    }, {
      "label": "Silvërspîre County Register of Deeds Sébastian Moonglôw to be retained",
      "options": [
        {
          "label": "Retain",
          "selection_limit": 375
        }, {
          "label": "Remove",
          "selection_limit": "CONTEST_LIMIT"
        }
      ]
    }
  ],
  "ballot_styles": [
    {
      "label": "Smoothstone County Ballot",
      "contests": [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ]
    }, {
      "label": "Silvërspîre County Ballot",
      "contests": [ 1, 3, 5, 7, 9, 11 ]
    }, {
      "label": "Wandering Wizard and Herbalist Ballot",
      "contests": [ 1, 2, 3, 4, 5, 6, 7, 8, 9 ]
    }
  ]
}
```

## Guardian Secret Key

The secret for Guardian N `guardian_N.SECRET_key.json` file is validated by the
[`guardian_secret_key.json`](./ElectionGuard_2.0_jsonschema/guardian_secret_key.json) schema file.

Example in non-canonical form:

```json
{
  "i": 1,
  "name": "Guardian 1",
  "secret_coefficients": [
    "77BF6C0EFD0689F8E7BDF91E30C969036993159711567FE7FD59794A860F06E3",
    "4B99BF5AD094A24A2700972F509522B0DE59DE4768A093F802E40572E34CE790",
    "5674483FED6C7685F90D9C214623865B1F5871D4A034ABC3B4277C1FF938938D"
  ],
  "coefficient_commitments": [
    "...1024 uppercase hex digits total...",
    "...1024 uppercase hex digits total...",
    "...1024 uppercase hex digits total..."
  ],
  "coefficient_proofs": [
    {
      "challenge": "6914FEAD42C83624679EDD7EEDAFA0C08A5998E9FD288D76FD0050DF78C2658D",
      "response": "73B968813B6C24EBB226A73987FA59A78BF852F38DDF6BC951CA611D8AF7BCE4"
    },
    {
      "challenge": "44283433C6E1ECD6900863AD2E5BC56BB4082F6A17C4600173E9297EEEB44581",
      "response": "9BD855F5CC57D12BB24BE24BA72D6056E3D5E8F7C7BBF030045B76F68EE1E950"
    },
    {
      "challenge": "C9189C54231ECBC2808C8F0E1D9C97EA24762E4A0F74D78F0B63485A4101A1A6",
      "response": "54F167B2DA733AE4B1A1A24AA76E3033024B50F2121C3B136652F2A0532517E0"
    }
  ]
}
```

## Guardian Public Key

The public `guardian_N.public_key.json` file is validated by the
[`guardian_public_key.json`](./ElectionGuard_2.0_jsonschema/guardian_public_key.json) schema file.

Example in non-canonical form:

```json
{
  "i": 1,
  "name": "Guardian 1",
  "coefficient_commitments": [
    "...1024 uppercase hex digits total...",
    "...1024 uppercase hex digits total...",
    "...1024 uppercase hex digits total..."
  ],
  "coefficient_proofs": [
    {
      "challenge": "6914FEAD42C83624679EDD7EEDAFA0C08A5998E9FD288D76FD0050DF78C2658D",
      "response": "73B968813B6C24EBB226A73987FA59A78BF852F38DDF6BC951CA611D8AF7BCE4"
    },
    {
      "challenge": "44283433C6E1ECD6900863AD2E5BC56BB4082F6A17C4600173E9297EEEB44581",
      "response": "9BD855F5CC57D12BB24BE24BA72D6056E3D5E8F7C7BBF030045B76F68EE1E950"
    },
    {
      "challenge": "C9189C54231ECBC2808C8F0E1D9C97EA24762E4A0F74D78F0B63485A4101A1A6",
      "response": "54F167B2DA733AE4B1A1A24AA76E3033024B50F2121C3B136652F2A0532517E0"
    }
  ]
}
```

## Extended Hashes

The public `hashes_ext.json` file is validated by the
[`hashes_ext.json`](./ElectionGuard_2.0_jsonschema/hashes_ext.json) schema file.

Example in non-canonical form:

```json
{
  "h_e": "E267134F945D7CAB120A9AD5FB23DAE29520605FD8FE4FA79E3F65DC36B2D0B8"
}
```

## Joint Election Public Key

The public `joint_election_public_key.json` file is validated by the
[`joint_election_public_key.json`](./ElectionGuard_2.0_jsonschema/joint_election_public_key.json)
schema file.

Example in non-canonical form:

```json
{
  "joint_election_public_key": "...1024 uppercase hex digits total..."
}
```

## Pre-voting Data

The `PreVotingData` structure is simply a collection of the structures that must be known
before ballots can be produced.

Example in non-canonical form:

```json
{
  "parameters": {
    "fixed_parameters": {
      "ElectionGuard_Design_Specification_version": {
        "number": [
          2,
          0
        ]
      },
      "generation_parameters": {
        "q_bits_total": 256,
        "p_bits_total": 4096,
        "p_bits_msb_fixed_1": 256,
        "p_middle_bits_source": "ln_2",
        "p_bits_lsb_fixed_1": 256
      },
      "field": {
        "q": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"
      },
      "group": {
        "p":  ...as before...
        "g":  ...as before...
        "q":  ...as before...
      }
    },
    "varying_parameters": {
      "n": 5,
      "k": 3,
      "info": "The United Realms of Imaginaria General Election 2024",
      "ballot_chaining": "Prohibited",
      "date": "2024-08-13"
    }
  },
  "manifest": {
    "label": "General Election - The United Realms of Imaginaria",
    "contests": [ ...as before... ],
    "ballot_styles": [ ...as before... ]
  },
  "hashes": {
    "h_p": "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296",
    "h_m": "201911B9B70665AB4E7C81F9C0AD0B2B0035BEF97EBE728AF0198CE4138F0BC3",
    "h_b": "B715EF39863A46D5C0D539AA0869EF18C7FDA022F47953969F5A56C66BBEB422"
  },
  "public_key": {
    "joint_election_public_key": "...1024 uppercase hex digits total..."
  },
  "hashes_ext": {
    "h_e": "6CDFB2F4750E7A6BF7D99D9E05E87784C2C9A289E3DBB2AC958670A38989231E"
  }
}
```

## VoterSelectionsPlaintext

This identifies a BallotStyle and voter selections. It is supplied as input to create a `Ballot`.

- Voter selections are present as plaintext.
- They have not been encrypted.
- The contest option fields contain voter selections. They have not had any
  encryption or selection limits applied.

Example of a ballot in `VoterSelectionsPlaintext` in non-canonical form:

```json
{
  "id": "00000-00001",
  "ballot_state": "VoterSelectionsPlaintext",
  "device": "Contoso Model SV-237 SN 98172-3645155",
  "creation_date": "2024-08-08T21:55:37Z",
  "contest_fields_plaintexts": {
    "1": { "field_values": [0, 1] },
    "2": { "field_values": [0, 0, 1, 0] },
    // ...
  },
}
```

## Ballot

A ballot can be in one of the following states:

* `PreEncrypted` - The ballot has been generated. It is
  - Includes a ballot identifier (`selection_encryption_identifier`)
  - Possibly associated with a specific device
  - It has encryptions of all possible voter selections, but
  - It has __no__ actual voter selections

* `VoterSelectionsEncrypted`,
  - Voter selections are completed and present in encrypted form.
  - The ballot has not yet been cast, challenged, or spoiled.
  - This is the initial state of a `Ballot` created by processing a
    `VoterSelectionsPlaintext` object with the `PreVotingData`.
  - The contest option fields from the `VoterSelectionsPlaintext` object may have been augmented
    with additional data fields. For example, additional data fields may indicate the
    voter selections exceeded selection limits.

* `Cast`
  - Voter selections are completed and present in encrypted form.
  - The ballot has been cast.
  - Selections MUST be considered to express voter intent, so
  - the ballot MUST NOT be decrypted.
  - Selections MUST be included in the tally.
  - This is a final state.

* `Spoiled`
  - Voter selections are completed and present in encrypted form.
  - The ballot has been spoiled, it will NOT be cast.
  - Selections MUST be considered as potentially expressing voter intent, so
  - the ballot MUST NOT be decrypted.
  - However, selections MUST NOT be included in the tally.
  - This is a final state.

* `Challenged`
  - Voter selections are completed and present in encrypted form.
  - The ballot has been challenged, it will never be cast.
  - Selections MUST NOT be interpreted as an expression of voter intent.
  - The ballot SHOULD be decrypted for verification.
  - Selections MUST NOT be included in the tally.

* `ChallengedDecrypted`
  * A challenged ballot in which voter selections have been decrypted.
  * Voter selections are present in both encrypted and plaintext form.
  * Selections MUST NOT be interpreted as an expression of voter intent.
  * Selections MUST NOT be included in the tally.
  * The challenged and decrypted ballot SHOULD be published.
  * This is a final state.

Example of a ballot in `VoterSelectionsEncrypted` state in non-canonical form:

```json
{
  "id": "00000-00001",
  "ballot_state": "VoterSelectionsEncrypted",
  "device": "Contoso Model SV-237 SN 98172-3645155",
  "creation_date": "2024-08-08T21:55:37Z",
  "contest_fields_ciphertexts": {
    "1": {
      "fields_ciphertexts": [
        { "alpha": "...",
          "beta": "..." },
        { "alpha": "...",
          "beta": "..." }
      ],
      "proofs_correctness": [
        { "c": "...",
          "v": "..." },
        { "c": "...",
          "v": "..." }
      ],
      "proofs_limits": [
        { "c": "...",
          "v": "..." },
        { "c": "...",
          "v": "..." }
      ],

    },
    // ...
  },
}
```

TODO

### Tally

The `Tally` contains the totals of the votes for each contest option.

Example in non-canonical form:

```json
```

### ElectionRecord

The `ElectionRecord` is formed by the combination of all public structures known after the tally has
been produced.

Example in non-canonical form:

```json
```

## References

|             |     |
| ----------- | --- |
| <a id="refs.RFC2119"></a>\[[RFC2119][RFC2119-html]] | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", [BCP 14](https://datatracker.ietf.org/doc/html/bcp14), [RFC 2119][RFC2119-html], DOI [10.17487/RFC2119](https://doi.org/10.17487/RFC2119), March 1997, <<https://www.rfc-editor.org/info/rfc2119>>. |
| <a id="refs.RFC3629"></a>\[[RFC3629][RFC3629-html]] \[[UTF-8][RFC3629-html]] | Yergeau, F., "UTF-8, a transformation format of ISO 10646", [STD 63](https://datatracker.ietf.org/doc/std63/ "IETF STD 63"), [RFC 3629][RFC3629-html], DOI [10.17487/RFC3629](https://doi.org/10.17487/RFC3629), November 2003, <<https://www.rfc-editor.org/info/rfc3629>>. |
| <a id="refs.RFC8174"></a>\[[RFC8174][RFC8174-html]] | Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", [BCP 14](https://datatracker.ietf.org/doc/html/bcp14 "IETF BCP 14"), [RFC 8174][RFC8174-html], DOI [10.17487/RFC8174](https://doi.org/10.17487/RFC8174), May 2017, <<https://www.rfc-editor.org/info/rfc8174>>. |
| <a id="refs.RFC8259"></a>\[[RFC8259][RFC8259-html]] | Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", [STD 90](https://datatracker.ietf.org/doc/std90/ "IETF STD 90"), [RFC 8259][RFC8259-html], DOI [10.17487/RFC8259](https://doi.org/10.17487/RFC8259), December 2017, <<https://www.rfc-editor.org/info/rfc8259>>. |
| <a id="refs.UNICODE"></a>\[[UNICODE][UNICODE-html]] | The Unicode Consortium, "The Unicode Standard", <<https://www.unicode.org/versions/latest/>>. |
| <a id="refs.EGDS20"></a>\[[EGDS20][EGDS20-pdf]] | Benaloh, J. and M. Naehrig, "ElectionGuard Design Specification Version v2.0.0", <<https://github.com/microsoft/electionguard-rust/tree/main/doc/specs>>. |
| <a id="refs.JSONSCHEMA"></a>\[[JSONSCHEMA][JSONSCHEMA-html]] | "JSON Schema Specification", <<https://json-schema.org/specification>>. |

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

[JSONSCHEMA-html]: https://json-schema.org/specification "JSON Schema Specification - json-schema.org"
[JSONSCHEMA]: #refs.JSONSCHEMA "JSON Schema Specification - json-schema.org"

[UNICODE-html]: https://www.unicode.org/versions/latest/ "The Unicode Standard (latest) - The Unicode Consortium"
[UNICODE]: #refs.UNICODE "The Unicode Standard (latest) - The Unicode Consortium"

[EGDS20-pdf]: https://github.com/microsoft/electionguard-rust/tree/main/doc/specs "ElectionGuard Design Specification v2.0 - MSR"
[EGDS20]: #refs.EGDS20 "ElectionGuard Design Specification v2.0 - MSR"
