# ElectionGuard 2.0 - Reference Implementation in Rust - Implementation Guide

## What Is This Document and Why Is It Important?

TODO

## Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Software Implementation

## Rust

### Calling this code from other languages

Rust has native support for defining `extern "C"` functions and data, so wrappers should it
should be straightforward to create them for almost any runtime environment. However, this
package does not supply them.

## Code organization and configuration

### Config values

* `allow_nonstandard_fixed_parameter_values` allow the use of values for p and q other than
  the standard values specified in the ElectionGuard 2.0 Reference Specification.
  When the standard values are used, some expensive primality checks can be avoided.

## Limits

In consideration of smaller platforms and languages and runtimes lacking good support
for unsigned integers, the maximum value of any quantity is generally limited to
`2^31 - 1` or `2,147,483,647`.

## Data types

## Text data, strings

Text data presents particular challenges for interoperability and
[internationalizability](https://www.w3.org/International/i18n-drafts/nav/about).

Text data used in ElectionGuard must be representable as valid UTF-8. For the Reference
Implementation in Rust, this is a requirement of Rust's
[String](https://doc.rust-lang.org/std/string/struct.String.html) type.

Humans tend to compare text without regard to upper/lower case distinctions. Perhaps because
this feels so natural to us, software developers tend to underestimate the implementation
complexity involved in concepts like 'equality', 'sorting', and 'case insensitivity' for text
across languages.

The [Unicode Standard](https://www.unicode.org/versions/latest/) specifies a number of
[Normalization Forms](https://www.unicode.org/reports/tr15/). Normalization "make[s] it possible
to determine whether any two Unicode strings are equivalent to each other".

[Unicode Technical Standard #10](https://www.unicode.org/reports/tr10/) specifies "how to compare
two Unicode strings" for sorting and equivalence. Version 15.0.0 is 70 pages long on my default
printer.

The Unicode Consortium [provides native Rust](https://github.com/unicode-org/icu4x) crates for
"Solving i18n for client-side and resource-constrained environments". Specific operations are
available as [individual crates](https://crates.io/crates/icu/dependencies).

Have a plan for equivalence comparison, normalization, case-folding, sorting, and formatting
rather than casually adopting functional requirements such as "sorted alphabetically" or
"case-insensitive string comparison".

Consider the possibility of homoglyph and encoding attacks TODO

Which will your application place first in sort order, "Precinct 2" or "Precinct 11"?

## Labels

Thankfully, ElectionGuard itself only needs to work with text data in a few places:

* Contest label
* Option label
* Ballot style label

A 'label' is intended to be a short, concise name or an identifier, not a long-form descriptions.

Due to the nature of the "elections" application domain, there may be very particular legal
requirements on the recording and presentation of these labels. Something to look into early
in your project planning.

ElectionGuard requires that these labels are unique within their collection. I.e., every Contest
has a label distinct from any other Contest. This means we'll need a defined function to determine
if two arbitrary labels are equal. The Rust
[Eq trait](https://doc.rust-lang.org/std/cmp/trait.Eq.html)
expresses this concept.

[Unicode Technical Standard #39](https://www.unicode.org/reports/tr39/) discusses security
considerations for identifiers and defines a "profile of identifiers in environments
where security is at issue".

See the [Serialization Specification TBD](TBD) for specific requirements.

## Guardian secrets

Guardians may re-use the same key for multiple elections if all guardians are the same and
n and k are the same.

There's an "election key" which is formed by the guardians

Analogy of building with one door and 4 locks.

Each guardian generates a their own secret key.
Guardians send each other messages to validate and cross-check each others' keys.
This cross-checking also serves as a back-up scheme allowing a quorum (k of n) of guardians to conduct the electionguard operations should one of them be unavailable.

## Structure of an election

### Roles in an election

#### Election Administrator

#### Election Guardians

Guardians have an essential role in fulfilling the privacy assurances
of ElectionGuard.

As a Guardian, the voters' privacy relies on you:

1. ***To REFUSE*** to reveal your Guardian secret key to ***anyone***, not even to the
Election Administrator. Using your secret key should not involve revealing it.

1. ***To REFUSE*** to use your Guardian secret key to decrypt any ballots other than those
that were intentionally challenged by the actual voter.

1. To be alert for the tactics that scammers, both traditional
and cyber-, use to trick people into enabling fraudulent actions unwittingly.

[County Password Inspector](https://www.smbc-comics.com/comic/2012-02-20)

1. To be present for the rehearsal and the formal Key and Tally Ceremonies with
your Guardian secret key.

1. To call a "time out" whenever something doesn't seem right.
Red flags:

* Unrehearsed, last-minute changes in plans or venue.
* Feeling pressured by time or people.
* Workarounds, or extra steps that weren't written down anywhere in advance.
* Trying to do multiple things at the same time.
* A feeling of too many balls in the air.
* Flattery or other personal persuasion.

The ceremonies should be deliberate, rehearsed, almost boring, procedures.

The right decision in almost every unclear situation is to pause to think,
express your concerns, gather more information,
re-state and question your assumptions.

1. To destroy your Guardian secret key at the appointed time after the election is over.

#### Voters

#### Political parties and voter-interest organizations

#### Journalists and other media

## Hardware requirements

### Gurardian secret key storage

#### Gurardian secret key operations

## Step-by-step

### Advance preparation

### Key ceremony

TODO come up with language that
TODO avoid mental model of guardians posessing a fraction of a key

### Tally ceremony

### Publishing

### Verification

### Reporting

## References

***Note*** Neither the ElectionGuard 2.0 Reference Specification nor this
Reference Implementation claims conformance to any official standards.
But it attempts to avoid gratuitous incompatibilities in the hope that it
will be straightforward to integrate within or interoperate with conformant
election systems.

[ElectionGuard Glossary](
https://www.electionguard.vote/overview/Glossary/
) at electionguard.vote

* Explicitly aims to conform with NIST CDF

[NIST Election Terminology Glossary](https://pages.nist.gov/ElectionGlossary/)

* "This glossary contains election terms including those used in the Voluntary Voting System
Guidelines 2.0 (VVSG 2.0) requirements and glossary and in the NIST Common Data Format (CDF)"

[NIST SP 1500-20 Ballot Definition Common Data Format Specification](
https://doi.org/10.6028/NIST.SP.1500-20
) "BD CDF"

* "This publication describes a ballot definition common data format for the interchange of logical
and physical ballot style information. It contains a UML (Unified Modeling Language) model of
the election data and a JSON (JavaScript Object Notation) and XML (eXtensible Markup
Language) format derived from the UML model. It contains background information regarding
how geopolitical geography is structured and used in the model and schemas. It also provides
usage examples for anticipated use-cases. The format is comprehensive and at the same time
very flexible, able to accommodate election scenarios used throughout the U.S. It is part of a
series of common data format specifications for voting equipment."

[NIST SP 1500-100r2 Election Results Common Data Format Specification](
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1500-100r2.pdf
) "CDF"

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

[Voluntary Voting System Guidelines 2.0](
https://www.eac.gov/sites/default/files/TestingCertification/Voluntary_Voting_System_Guidelines_Version_2_0.pdf
) "VVSG"

* "This document will be used primarily by voting system manufacturers and voting system test
laboratories as a baseline set of requirements for voting systems to which states will add their
state-specific requirements as necessary. [...] This document, therefore, serves as an important,
foundational tool that defines a baseline set or requirements necessary for ensuring that the
voting systems used in U.S. elections will be secure, reliable, and easy for all voters to use
accurately."

[Google Civics Common Standard Data Specification](https://developers.google.com/civics-data)

* Wherever they conflict, the NIST CDF is authoritative.
