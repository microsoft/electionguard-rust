# ElectionGuard 2.0 - Data Serialization Specification - Version 0.0.1 - 2023-11-10

# Overview

## What Is This Document and Why Is It Important?

This document specifies in detail how the data structures ("objects")
of the ElectionGuard 2.0 Design Specification are to be encoded into bytes.

Specifying this in detail is of vital importance for several reasons:

* ElectionGuard objects represent data artifacts created during the course of an
election and are the vehicles through which meaningful assurances of election
integrity are provided.

* The assurances provided by ElectionGuard rely on these objects' content (and
in some cases even their exact byte sequences) being preserved when exchanged
across time, storage devices, networks, administrators, verifier apps, and
other heterogeneous elections systems.

* Some data artifacts function as cryptographic commitments or intermediate computations
from which the proofs of integrity and correctness of tallies ultimately derive.
If these were to become lost, corrupted, or fail to exchange between systems, the
integrity assurances provided by ElectionGuard could be significantly weakened or
delayed.

* The ElectionGuard 2.0 Design Specification specification is intended to enable
and encourage the growth of an entire ecosystem of independently developed,
interoperable implementations. The availability from the beginning of a complete,
consistent, and straightforward-to-implement protocol specification is key to bringing this vision to reality.

The serialization format is defined in terms of widely-used industry standards,
and is intended to allow the use of existing off-the-shelf libraries to the
extent practical.

## Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Purposes of Serialization

### Persistence

### Publication

### Data Exchange/Interchange

### Ceremonial artifacts

## Requirements of Serialized Objects

### Integrity

TODO discuss authenticity

TODO discuss hash

### Durability

It must be practical to store these objects in a manner by which they can not be lost.

### Compatibility

The serialized objects must be written in a widely-supported format.of 

## Usage of JSON

### Similarities

### High-level

### H3

### H3

## Representation of numbers

As a cryptographic system, ElectionGuard is heavily based on numbers.
The specific type of cryptography used employs exclusively non-negative integers.
Although this makes things simple in some ways, there are some special requirements
that requrire consideration.

## Character encoding

All serialized data MUST be encoded using UTF-8 with no leading BYTE ORDER MARK (BOM).

However, the U+FEFF "ZERO WIDTH NO-BREAK SPACE" character is allowed within string values
where arbitrary text is allowed.

[[RFC 3629] UTF-8, a transformation format of ISO 10646](https://www.rfc-editor.org/rfc/rfc3629.html)

## JSON

[[RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format](https://datatracker.ietf.org/doc/html/rfc8259)

The ElectionGuard Reference Implementation in Rust can emit two related, but distinct, representation:
The canonical storage format, and the "pretty" format.

Although both formats SHOULD produce the same result from a typical JSON parser, they
are completely different.

### Canonical representation

* Required for implementations to produce.
* Required for implementations to consume.
* The first byte is always an opening `'{'` and the last byte the matching `'}'`.
* Contains absolutely no unnecessary characters, such as formatting spaces, not even
a terminating `CR`, `LF`, or `CRLF` sequence.
* In this respect it may be considered a "binary" file format.
* The content has a well-defined and consistent hash value. It may be hashed in
memory as an array of bytes, or written to a file and hashed using a filesystem
utility. Both methods MUST produce the same hash value.
* Although it MAY be opened and viewed with a plain-text application, it probably won't be
particularly easy to understand the structure.

### Pretty representation

* MAY be produced by a straightforward transformation from the canonical representation.
* Is not defined bit-for-bit, so MAY NOT yield a stable or well-defined hash value.
* MUST NOT be included in any hash computations.
* SHOULD NOT be included in any official reporting processes, except directly along  included .

However, only the canonical format is requried by this specification.

| Canonical | Pretty         |        |
| --------- | -------------- | ------
| Required  | Optional       | for implmenters to produce. 
| Required  | Optional       | for implmenters to consume. 
| Condensed | Spaced legibly | for easier reading by humans. 
| Official  | Informational  | in hashing, signing, and verification operations.

The JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using
UTF-8

The JSON format, as a near-subset of ECMAScript, represents all numbers as double precision
floating point values. As this format is unable to accurately represent integers larger
than `2^53 - 1`, it is unsuitable for representing the large integers used by ElectionGuard.

However, JSON number values are used when the ElectionGuard 2.0 Specification guarantees that their
range will be limited, such as the index values limited to `2^31 - 1`.

### Order of members in an object

The JSON specification states that "The names within an object SHOULD be unique." This specification
goes farther and requires that they MUST be unique.

The JSON specification, as well as existing practice, does not take a position on whether the order of
object names has semantic meaning. It notes that many parsing libraries do not expose this order to
the consumers of the data structure. However, ElectionGuard objects serialized in canonical form
are hashed, so such details matter.

Writers of canonical form objects MUST list the object members in the specified order.

Readers of canonical form objects MAY ignore the order of object members (except for hash comparisons).

### H3

## Integers
The byte sequence representation of 'mod p' and 'mod q' values is already defined in the spec to be fixed length of the minimum number of bytes required to represent p or q.

For serialization in ASCII string-based formats (such as JSON), implementations SHOULD encode this byte sequence
using base64 as defined by [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html).

This RFC states that: "Implementations MUST include appropriate pad characters at the end of encoded data unless the specification referring to this document explicitly states otherwise." So, insofar as there is no official specification for serialization beyond these guidelines, you SHOULD include the padding in the base64.

### H3

### H3

## H2

### H3

### H3


TODO Json structure

TODO Ideally, messages for the key ceremony should be concise enough that they can printed and recognized with OCR or a simple barcode symbology,
thus preventing the requirement for IP network connectivity between the guardian PCs.





