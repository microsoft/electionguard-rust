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

The public `election_parameters.json` file is validated by the
[`election_parameters.json`](./ElectionGuard_2.0_jsonschema/election_parameters.json) schema file.

Example in non-canonical pretty form:

```json
{
  "fixed_parameters": {
    "ElectionGuard_Design_Specification": {
      "Official": {
        "version": [
          2,
          0
        ],
        "release": "Release"
      }
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
    "date": "2024-08-05",
    "info": "The United Realms of Imaginaria General Election 2024",
    "ballot_chaining": "Prohibited"
  }
}
```

### Hashes

The public `hashes.json` file is validated by the
[`hashes.json`](./ElectionGuard_2.0_jsonschema/hashes.json) schema file.

Example in non-canonical pretty form:

```json
{
  "h_p": "2B3B025E50E09C119CBA7E9448ACD1CABC9447EF39BF06327D81C665CDD86296",
  "h_m": "7CAAAD91B51C5EF9E406EBFACA47AACB5C9BDA82D553719A0279076ED1E284C9",
  "h_b": "722346503D070901DEC5EF88BA06135FDCB0BC10BB4F918EC45F4EF57C481896"
}
```

### Election Manifest

The public `election_manifest_canonical.bin` file is validated by the
[`election_manifest.json`](./ElectionGuard_2.0_jsonschema/election_manifest.json) schema file.

Example in non-canonical pretty form:

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

The secret for Guardian N `guardian_N.SECRET_key.json` file is validated by the
[`guardian_secret_key.json`](./ElectionGuard_2.0_jsonschema/guardian_secret_key.json) schema file.

Example in non-canonical pretty form:

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
    "C2A7DFAAE02425A7F3E50AC8691393C74BC6F2E21E6B25955A1DBAED2E9D14D23E83D989B0D529BB675207D90F7C025DC068D418DACBDCC086234B87E8235ECE4A6482DD938EC824CDFCE12345C586685DB70595BD10951FE24774B3DD52637EBDBF25C694F73163F37B7F64CA3E6FD63404BFD1FB1C9AEA4573F36C9B43467EFF789021BA6DC7A43EE6D5E8EFF9CFC70BC18D0CBA8A712439E386C6C23BE6CFAD579E7BB8A087DA77CF4C938E8765C5A0B0E564065DB2701D785183A549B821687E87D46CE635AC8B9F7E8AC0CA1E3BB5268FA39B9C92ED7D30882E1DC7F734FED73D3CB7522D242BE185965E87FD302FB1A809394376B6E8A219E8B960328C4B6BEC1F42183038FE9B95DB8A9803FBD8DCE345A79E811D49921B9D908A958F1DCB5DB10AE9D26552896346726626BE600AF7318397256477E9CE020534931A2AA26DD0A8ACD4A2597F4D0BA24F8378A6C9EC6EC7A0E11412228C8415CF1805133C17157555465641F58AAFB8E2AD8FD1718500B27FE4DEF5C46F99FFFF982F88EC4229FCD347E746317DCEDCD60B7B9C54FBBA3847707A80EEB71AB1F2558D9C09E8A5A25981363F8F59CECBCDA7AAF1666E4B37A041D5A95B6FA5046808F99C09E3894779A3E8ABED23B4F14FFEF6B929D9C8F06A39E5C94F1C2BD2DCAF5ED6E5D30C6DED9BFB83721A69E253FA8FA067D18F923D0B07AE5ADF1D71A4EE5C",
    "75EFDB0BF483B504C451BE856DE969D7835CFE8251C2B3C2BF006552A02342E6EFEEDB7E6B923D964BE063E075EF37EB91EED872886B9D92CF3937824BD17DEA2154AEE2C205461A12930917908586F2D35C936C992C4C39F1F02BF5C9641B6230836EB8C37A4C86D1BCB7CA3191E0ED1C06BFBB3E6C39DC86FF036178A8FC0CE7F7709BD5F5119ED81EEBAFB8E588B3FABAD5B3213B9B24698F37B4A4FA919BA831F8E3B180B75D8E44CD2B949BE4F1A4D2342C43DA7BD8E978DDD00076BC048C5B964ADDD507011B293EC7D96EFC0A72349D9EC453E076C917E0C6391198FD3E5A1E1F15CD65045FA030306B6C63CDA88F2BFB0EFACD367F50E952D3CD93C7B62123BD7F658C4C16BCD28622FAF1B0CF01E869182D79A7B28371DFFAC9D6D04E6836C8BD34643FCEC9E2B88F6812021E1A7CC6022203876A9D49D9460B61461191443538C7A0A80CAC5B17243A0860676D075A54E997E27F4D4A7FBD19777689C249006E829AF10ECCF1878FE8015FD35175F0E6B7B7B984950C8F9DF458BDCC02E2BAB92DFA10D8C8094D4AC8ECBDF8D4071BD3864B52873A62C3FEAF728B9DC944E1E8CD741614105054017AAED6F1D62F39677727364F1D646C60846B1B98AA12B1D430392C9E516C913F3B1238A417D1C2A8A45D4C2724094E1A2F34A9524F665FC50A82A424FA1E35CB4744338D21768D9E2FBE1A0C09FA6CB263F36E",
    "54D4DB5B7B9C37134D66D9502FC10DE734703D5F0041400E904D1A67E156ACE512070BECA9E8C03551FEB1AA225769B63A36E524C50220CDCD49E2955F1EEF9082E937E6B071337E8873C7E44F03B430F2ABA9BE54D6658227365510F3F11C5A701E9BB46DA525C2F6C29F91DFB20A5A8500C2A5FD784B0761F20B77846D1332A15DDD1C724639DA28B3066FAC99B7D211C80F24C4C96AA27D0F6B72C914D66C090586A9B39E58C8E67014D6D5A69D7E7932E2D2BF1248B5835B732979AAF7C2C7B5ED28D552B3AEFE4A6B697869043DBF802CC29E036CB10974771BAC7117CB9F8795086BFBB9621071AC1E938C9FECD08678FB5A0DB2EC524D8E2677E9C7DF41E075AB6F1A8A056A0B8D37F8E8B571BFB130A82DDCB0A2603D1B375E6A28317D96408DFEA8700E4A3FF119761D3A3D520B3C496B9F3C060D1C5F9FB6254E7FE029984B788650E6578BC1B732184BD97B9AF46A4E245F14E0872BC21779094D3A24EB00D1B42257282E0B76AE9BF7835CAD9F5EA59B7B0C8BDE50EE71EB2D5D8C5F2AA9DD32BA408C51A676E46EDA81FEEBACCF77F1CDF166A2ACEE6F4C9F74D70B282C8F24FC84F47B5152EB65634E78E68CC4C4A25EE23F94B9E95298CB34D76EF6B53D3EE55705C79A90775CD16F88125DB3302069397CC20BF7BE242F145379138993CEE429C58B11C79D6383449DD68FE0291F1EA01E48B564106F3486"
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

### Guardian Public Key

The public `guardian_N.public_key.json` file is validated by the
[`guardian_public_key.json`](./ElectionGuard_2.0_jsonschema/guardian_public_key.json) schema file.

Example in non-canonical pretty form:

```json
{
  "i": 1,
  "name": "Guardian 1",
  "coefficient_commitments": [
    "C2A7DFAAE02425A7F3E50AC8691393C74BC6F2E21E6B25955A1DBAED2E9D14D23E83D989B0D529BB675207D90F7C025DC068D418DACBDCC086234B87E8235ECE4A6482DD938EC824CDFCE12345C586685DB70595BD10951FE24774B3DD52637EBDBF25C694F73163F37B7F64CA3E6FD63404BFD1FB1C9AEA4573F36C9B43467EFF789021BA6DC7A43EE6D5E8EFF9CFC70BC18D0CBA8A712439E386C6C23BE6CFAD579E7BB8A087DA77CF4C938E8765C5A0B0E564065DB2701D785183A549B821687E87D46CE635AC8B9F7E8AC0CA1E3BB5268FA39B9C92ED7D30882E1DC7F734FED73D3CB7522D242BE185965E87FD302FB1A809394376B6E8A219E8B960328C4B6BEC1F42183038FE9B95DB8A9803FBD8DCE345A79E811D49921B9D908A958F1DCB5DB10AE9D26552896346726626BE600AF7318397256477E9CE020534931A2AA26DD0A8ACD4A2597F4D0BA24F8378A6C9EC6EC7A0E11412228C8415CF1805133C17157555465641F58AAFB8E2AD8FD1718500B27FE4DEF5C46F99FFFF982F88EC4229FCD347E746317DCEDCD60B7B9C54FBBA3847707A80EEB71AB1F2558D9C09E8A5A25981363F8F59CECBCDA7AAF1666E4B37A041D5A95B6FA5046808F99C09E3894779A3E8ABED23B4F14FFEF6B929D9C8F06A39E5C94F1C2BD2DCAF5ED6E5D30C6DED9BFB83721A69E253FA8FA067D18F923D0B07AE5ADF1D71A4EE5C",
    "75EFDB0BF483B504C451BE856DE969D7835CFE8251C2B3C2BF006552A02342E6EFEEDB7E6B923D964BE063E075EF37EB91EED872886B9D92CF3937824BD17DEA2154AEE2C205461A12930917908586F2D35C936C992C4C39F1F02BF5C9641B6230836EB8C37A4C86D1BCB7CA3191E0ED1C06BFBB3E6C39DC86FF036178A8FC0CE7F7709BD5F5119ED81EEBAFB8E588B3FABAD5B3213B9B24698F37B4A4FA919BA831F8E3B180B75D8E44CD2B949BE4F1A4D2342C43DA7BD8E978DDD00076BC048C5B964ADDD507011B293EC7D96EFC0A72349D9EC453E076C917E0C6391198FD3E5A1E1F15CD65045FA030306B6C63CDA88F2BFB0EFACD367F50E952D3CD93C7B62123BD7F658C4C16BCD28622FAF1B0CF01E869182D79A7B28371DFFAC9D6D04E6836C8BD34643FCEC9E2B88F6812021E1A7CC6022203876A9D49D9460B61461191443538C7A0A80CAC5B17243A0860676D075A54E997E27F4D4A7FBD19777689C249006E829AF10ECCF1878FE8015FD35175F0E6B7B7B984950C8F9DF458BDCC02E2BAB92DFA10D8C8094D4AC8ECBDF8D4071BD3864B52873A62C3FEAF728B9DC944E1E8CD741614105054017AAED6F1D62F39677727364F1D646C60846B1B98AA12B1D430392C9E516C913F3B1238A417D1C2A8A45D4C2724094E1A2F34A9524F665FC50A82A424FA1E35CB4744338D21768D9E2FBE1A0C09FA6CB263F36E",
    "54D4DB5B7B9C37134D66D9502FC10DE734703D5F0041400E904D1A67E156ACE512070BECA9E8C03551FEB1AA225769B63A36E524C50220CDCD49E2955F1EEF9082E937E6B071337E8873C7E44F03B430F2ABA9BE54D6658227365510F3F11C5A701E9BB46DA525C2F6C29F91DFB20A5A8500C2A5FD784B0761F20B77846D1332A15DDD1C724639DA28B3066FAC99B7D211C80F24C4C96AA27D0F6B72C914D66C090586A9B39E58C8E67014D6D5A69D7E7932E2D2BF1248B5835B732979AAF7C2C7B5ED28D552B3AEFE4A6B697869043DBF802CC29E036CB10974771BAC7117CB9F8795086BFBB9621071AC1E938C9FECD08678FB5A0DB2EC524D8E2677E9C7DF41E075AB6F1A8A056A0B8D37F8E8B571BFB130A82DDCB0A2603D1B375E6A28317D96408DFEA8700E4A3FF119761D3A3D520B3C496B9F3C060D1C5F9FB6254E7FE029984B788650E6578BC1B732184BD97B9AF46A4E245F14E0872BC21779094D3A24EB00D1B42257282E0B76AE9BF7835CAD9F5EA59B7B0C8BDE50EE71EB2D5D8C5F2AA9DD32BA408C51A676E46EDA81FEEBACCF77F1CDF166A2ACEE6F4C9F74D70B282C8F24FC84F47B5152EB65634E78E68CC4C4A25EE23F94B9E95298CB34D76EF6B53D3EE55705C79A90775CD16F88125DB3302069397CC20BF7BE242F145379138993CEE429C58B11C79D6383449DD68FE0291F1EA01E48B564106F3486"
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

### Extended Hashes

The public `hashes_ext.json` file is validated by the
[`hashes_ext.json`](./ElectionGuard_2.0_jsonschema/hashes_ext.json) schema file.

Example in non-canonical pretty form:

```json
{
  "h_e": "E267134F945D7CAB120A9AD5FB23DAE29520605FD8FE4FA79E3F65DC36B2D0B8"
}
```

### Joint Election Public Key

The public `joint_election_public_key.json` file is validated by the
[`joint_election_public_key.json`](./ElectionGuard_2.0_jsonschema/joint_election_public_key.json) schema file.

Example in non-canonical pretty form:

```json
{
  "joint_election_public_key": "0193E1118F54F001395C3AA7F33596ED178E3B3228EF644C694561F530D68B50F06D27FD9DAD2468B3842711685B7ADDB3C7CD882F1644B695C8E0228B7CECFAC05E5BCA85DD6D83B43940310D9CF48E9641641FA8244A5996A086F811E7157552F4EECC1441782738E940DDDE312EEA3CD296666735FB68F38EE288539035F88695E9DC1495E5013BCDB75FB1F440B9D1F99BEE915A06B4DB327608CC219D0FBEC3B561D94EA7AC4DB92D69370C2BC76EF43BD68357DB312015A28731F9E8ECFA3C757765CB4A0FDDE14ABD892EB700C7ADDD833C4A29BD23424424597FFC57FE70CE2EE1461A83E277D903FEFF41AE7AA0AABF3B4D5A3F8EFC0703E6638EED2E279B01EE28B896F4E0326037DC0C63894DFDCAC95BC462489A0E72C75CE9AA24FF21A160B44F6EE109274334784F16D6AD8E4E4A38BF9F847018C12E06633E5D6D15192F2154E9E9A392314722C71F1F99860F6B6F4120BCCAFCC4CBA0C3DE8DD36ACE0A551FC14FEEB6929BEDA076060A4AB93D46ADC2E91D69B1089FB3DDB4B622D099FC1EA59C2D5A71058E81EFCD97F9E55ED7D6809578375D8F6562BDC843F5F93D7B105FEC6061A51EB785A3D751D400240DB66D49F8A4549D036C613938CF5906FBA35762F235EC2EA30D2C8C7913F2572AD3F27EF1D6A5FE98654649685EBAAD71BADC953DC0122F171F8A9438E7EC9689B16380174E701656593C"
}
```

### Pre-voting Data

TODO

### Ballot Voter Selections Plaintext

TODO

### Ballot Voter Selections Encrypted

TODO

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
[EGDS20]: #refs.EGDS "ElectionGuard Design Specification v2.0 - MSR"
