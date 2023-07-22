# ElectionGuard 2.0 Reference Implementation in Rust

> "ElectionGuard is a way of checking election results are accurate, and that votes have
> not been altered, suppressed or tampered with in any way. Individual voters can see that
> their vote has been accurately recorded, and their choice has been correctly added to
> the final tally. Anyone who wishes to monitor the election can check all votes have been
> correctly tallied to produce an accurate and fair result."
>
> &nbsp; &nbsp; &nbsp; &nbsp; — From [What is ElectionGuard?](
    https://news.microsoft.com/on-the-issues/2020/03/27/what-is-electionguard/)
>

Although ElectionGuard is designed to be an industrial-strength solution to help secure
traditional civic elections, it can also be used for "low stakes" forms of polling as well.

Consider ElectionGuard anywhere the security and privacy properties provided by homomorphic
tallying could be beneficial.

# Project status: INCOMPLETE, <span style="color:red">**EXPERIMENTAL**</span>

## What is this project in particular and where does it fit in?

This project is an open source Rust implementation of ElectionGuard 2.0,
intended to serve as a reference or as production software for those wishing to incorporate
ElectionGuard into their systems.

The Rust Language was chosen for this reference implementation due to its:
- Innovative memory safety guarantees and excellent security and reliability track record
- Strong, static, well-defined, type system
- Runtime performance
- Cross platform compatibility and ability to integrate with external code defined in C
- Clean and consistent design

This is not the only implementation of ElectionGuard, some others are listed below.

## Documentation

### In this source distribution:

* [BUILDING](./BUILDING.md) How to build and run the code in this repository 👈 *** **Start here** ***
* [SECURITY](./SECURITY.md) Reporting security issues
* [SUPPORT](./SUPPORT.md) How to engage with developers and community
* [CODE_OF_CONDUCT](./CODE_OF_CONDUCT.md) We are committed to providing a welcoming and inspiring community for all
* [README](./README.md) You're reading me now

### Built from sources:

* [Table of Contents](./src/target/doc/table_of_contents.html) Top level project documentation. 👈 Bookmark
this after you get it built.

## More information

Brought to you by:

* [Microsoft Research Lab – Redmond](https://www.microsoft.com/en-us/research/lab/microsoft-research-redmond/)
   - [Special Projects](https://www.microsoft.com/en-us/research/group/microsoft-research-special-projects/)
     - [Security and Cryptography](https://www.microsoft.com/en-us/research/group/security-and-cryptography/) group

- ... with help and contrbutions from many others.

Videos
* Tutorial, Research talk, and Q&A:
  - Tutorial: ElectionGuard: Enabling voters to verify election integrity
       - Josh Benaloh, Senior Principal Cryptographer, Microsoft Research Redmond
  - Research talk: ElectionGuard: Implementations and future directions
       - Dan S. Wallach, Professor, Rice University
  - Microsoft Research Summit 2021 - The Future of Privacy & Security - [event page](https://www.microsoft.com/en-us/research/video/tutorial-research-talk-and-qa-electionguard-enabling-voters-to-verify-election-integrity/)
  - Direct link to [video on YouTube](https://www.youtube.com/watch?v=U7Ewg95o48U)

ElectionGuard website:
* [electionguard.vote](http://www.electionguard.vote/)

## Other projects

This section is a list of pointers to independent projects which those
who are interested in ElectionGuard and related technologies may find interesting.
*It is not intended to be comprehensive or authoritative. Inclusion here should not be
interpreted as meaningful in any way, and in particular not as an endorsement of any kind.
Independent projects are independent.*

This list is known to be incomplete. Suggestions are welcome.

### ElectionGuard 2.0

- [ElectionGuard 2.0 Reference Implementation in Rust](https://github.com/microsoft/electionguard-rust) This project
- [ElectionGuard 2.0 in Kotlin](https://github.com/danwallach/electionguard-kotlin-multiplatform) from Dan Wallach of Rice University

### ElectionGuard 1.x

- [ElectionGuard 1.x in Python](https://github.com/microsoft/electionguard-python) [docs](https://microsoft.github.io/electionguard-python/) from Microsoft
- [ElectionGuard 1.x API in C](https://github.com/microsoft/electionguard-c) from Microsoft [No longer maintained]
- [ElectionGuard 1.x API in C#](https://github.com/microsoft/electionguard-dotnet) from Microsoft [No longer maintained]
- [ElectionGuard 1.x SDK Reference Verifier]() from Microsoft

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
