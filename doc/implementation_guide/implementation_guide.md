# ElectionGuard 2.0 Reference Implementation in Rust - Implementation Guide

Version 2.0.0, 2023-07-07

## Key words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Scope

TODO

## Rust

### Calling this code from other languages

Rust has native support for defining `extern "C"` functions and data, so wrappers should it should be straightforward
to create them for almost any runtime environment. However, this package does not supply them.

### Vendor plugin support

## Text data, strings

Text data presents particular challenges for interoperability and [internationalizability](https://www.w3.org/International/i18n-drafts/nav/about).

Text data used in ElectionGuard MUST:
* Be representable as valid UTF-8. This derives from the requirements of Rust's [std::string::String](https://doc.rust-lang.org/std/string/struct.String.html) type.
* Consider the possibility of homoglyph and encoding attacks TODO

Humans tend to compare text without regard to upper/lower case distinctions. Perhaps because this feels so natrual
to us, software developers tend to underestimate the implementation complexity involved in concepts
like 'equality', 'sorting', and 'case insensitivity' for text across languages.

The [Unicode Standard](https://www.unicode.org/versions/latest/) specifies a number of
[Normalization Forms](https://www.unicode.org/reports/tr15/). Normalization "make[s] it possible to
determine whether any two Unicode strings are equivalent to each other".

[Unicode Technical Standard #10](https://www.unicode.org/reports/tr10/) specifies "how to compare two
Unicode strings" for sorting and equivalence. Version 15.0.0 is 70 pages long on my default printer.

The Unicode Consortium [provides native Rust](https://github.com/unicode-org/icu4x) crates for
"Solving i18n for client-side and resource-constrained environments". Specific operations are
available as [individual crates](https://crates.io/crates/icu/dependencies).

Have a plan for equivalence comparison, normalization, case-folding, sorting, and formatting
rather than casually adopting functional requirements such as "sorted alphabetically" or "case-insensitive string comparison".

Which will your application place first in sort order, "Precinct 2" or "Precinct 11"?

## Labels

Thankfully, ElectionGuard itself only needs to work with text data in a few places:
* Contest label
* Option label
* Ballot style label
* TODO more places may be coming with preencrypted ballots

A 'label' is intended to be a short, concise name or an identifier, not a long-form descriptions.

Due to the nature of the "elections" application domain, there may be very particular legal
requirements on the recording and presentation of these labels. Something to look into early
in your project planning.

ElectionGuard requires that these labels are unique within their collection. I.e., every Contest
has a label distinct from any other Contest. This means we'll need a defined function to determine if
two arbitrary labels are equal. The Rust [std::cmp::Eq trait](https://doc.rust-lang.org/std/cmp/trait.Eq.html)
expresses this concept.

[Unicode Technical Standard #39](https://www.unicode.org/reports/tr39/) discusses security considerations
for identifiers and defines a "profile of identifiers in environments where security is at issue".

* TODO Most US ballots I've seen do have line breaks in the contest options. The first line may not even include the name of the candidate. But results reporting always seems to have a way to refer to both candidates and their percentages along the bottom edge of a TV screen. Do we need to allow them?

Labels MUST:
* Conform to the requirements for text data described above
* Define an equivalence relation that is reflexive and symmetric.
* Be processed with regard to 

Labels SHOULD:
* Be human readable and human meaningful
* Contain enough detail to identify the item uniquely
* Be plain text
* Use a single 0x20 for a whitespace character where possible
* Be compatible with NIST 1500-100 [ref]

Labels SHOULD NOT:
* Include line breaks, tabs, or formatting characters beyond what is necessary to accurately represent the text.
* Be used to store higher level formats such as HTML or JSON. Vendor data fields are provided for that.
* Have contiguous sequences of multiple whitespace characters other than a single 0x20.
* Have leading or trailing whitespace characters

*TODO watch for and harmonize with incoming change to EG Spec defining 'label'
SHOULD not have leading or trailing whitespace characters

= Labels and string data

## Integers
The byte sequence representation of 'mod p' and 'mod q' values is already defined in the spec to be fixed length of the minimum number of bytes required to represent p or q.

For serialization in ASCII string-based formats (such as JSON), implementations SHOULD encode this byte sequence
using base64 as defined by [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html).

This RFC states that: "Implementations MUST include appropriate pad characters at the end of encoded data unless the specification referring to this document explicitly states otherwise." So, insofar as there is no official specification for serialization beyond these guidelines, you SHOULD include the padding in the base64.

## Guardian secrets

Guardians may re-use the same key for multiple elections. Perhaps this should be explicitly stated in the EG spec.

## Structure of an election

### References

***Note*** Neither the ElectionGuard 2.0 Reference Specification nor this
Reference Implementation claims conformance to any official standards.
But it attempts to avoid gratuitous incompatibilities in the hope that it
will be straightforward to integrate within or interoperate with conformant
election systems.

[ElectionGuard Glossary](https://www.electionguard.vote/overview/Glossary/) at electionguard.vote
* Explicitly aims to conform with NIST CDF

[NIST Election Terminology Glossary](https://pages.nist.gov/ElectionGlossary/)
* "This glossary contains election terms including those used in the Voluntary Voting System Guidelines 2.0
(VVSG 2.0) requirements and glossary and in the NIST Common Data Format (CDF)"

[NIST SP 1500-20 Ballot Definition Common Data Format Specification](https://doi.org/10.6028/NIST.SP.1500-20)
"BD CDF"
* "This publication describes a ballot definition common data format for the interchange of logical 
and physical ballot style information. It contains a UML (Unified Modeling Language) model of 
the election data and a JSON (JavaScript Object Notation) and XML (eXtensible Markup 
Language) format derived from the UML model. It contains background information regarding 
how geopolitical geography is structured and used in the model and schemas. It also provides 
usage examples for anticipated use-cases. The format is comprehensive and at the same time 
very flexible, able to accommodate election scenarios used throughout the U.S. It is part of a 
series of common data format specifications for voting equipment."

[NIST SP 1500-100r2 Election Results Common Data Format Specification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1500-100r2.pdf)
"CDF"
* "This publication describes an election results common data format specification for pre-election
setup information and post-election results reporting. It contains a UML (Unified Modeling 
Language) model of the election data and an XML (eXtensible Markup Language) and JSON 
(JavaScript Object Notation) format derived from the UML model. It also contains background 
information regarding how geopolitical geography is structured and used in the model and 
schema. The XML format is comprehensive and at the same time very flexible, able to 
accommodate election scenarios used throughout the U.S. It is part of a series of planned 
common data format specifications for voting equipment"

[NIST CDF Test Data Sets](https://github.com/usnistgov/cdf-test-method/tree/main/test_data)
* Six different test elections with completed ballots.
* Suggested to start with GEN-03, then 02, then 01.

[Voluntary Voting System Guidelines 2.0](https://www.eac.gov/sites/default/files/TestingCertification/Voluntary_Voting_System_Guidelines_Version_2_0.pdf)
"VVSG"
* "This document will be used primarily by voting system manufacturers and voting system test 
laboratories as a baseline set of requirements for voting systems to which states will add their 
state-specific requirements as necessary. [...] This document, therefore, serves as an important,
foundational tool that defines a baseline set or requirements necessary for ensuring that the
voting systems used in U.S. elections will be secure, reliable, and easy for all voters to use accurately."

[Google Civics Common Standard Data Specification](https://developers.google.com/civics-data)
* Wherever they conflict, the NIST CDF is authoritative.

## Requirements for election systems vendors

## Requirements for verifier app authors

## Roles

#### Election Administrator

#### Election Guardians

#### Voters

#### Political parties and voter-interest organizations

#### Journalists and other media

## Hardware requirements

### Gurardian secret key storage

### Gurardian secret key operations

## Step-by-step Operation

### Advance preparation

### Key ceremony

### Tally ceremony

### Publishing

### Verification

### Reporting
