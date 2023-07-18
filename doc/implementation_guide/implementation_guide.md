# ElectionGuard 2.0 Implementation Guide

Version 0.0.1, 2023-07-07

## Key words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Scope

TODO

## Text data, strings

Text data presents particular challenges for interoperability and [internationalizability](https://www.w3.org/International/i18n-drafts/nav/about).

Text data used in ElectionGuard MUST:
* Be representable as valid UTF-8. This derives from the requirements of Rust's [std::string::String](https://doc.rust-lang.org/std/string/struct.String.html) type.
* Consider the possibility of homoglyph and encoding attacks TODO

Humans tend to compare text without regard to upper/lower case distinctions. Perhaps because this feels so natrual
to us, software developers tend to underestimate the implementation complexity involved in concepts
like 'equality', 'sorting', and 'case insensitivity' for text across languages.

The [Unicode Standard](https://www.unicode.org/versions/latest/) specifies a number of
[Normalization Forms](https://www.unicode.org/reports/tr15/). Normalization "make[s] it possible to determine
whether any two Unicode strings are equivalent to each other".

[Unicode Technical Standard #10](https://www.unicode.org/reports/tr10/) specifies "how to compare two Unicode strings"
for sorting and equivalence. Version 15.0.0 is 70 pages long on my default printer.

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
Any base64 representation of these quantities is the base64 of this byte sequence.

## Guardian secrets

Guardians may re-use the same key for multiple elections. Perhaps this should be explicitly stated in the EG spec.

# TODO Things yet to discuss

* Most US ballots I've seen do have line breaks in the contest options. Do we need to allow them?

## Calling this code from other languages

Rust has native support for defining `extern "C"` functions and data, so wrappers should it should be straightforward
to create them for almost any runtime environment. However, this package does not supply them.
