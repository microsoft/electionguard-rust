# ElectionGuard 2.0 Rust Reference Implementation

## What is ElectionGuard?

From [What is ElectionGuard?](https://news.microsoft.com/on-the-issues/2020/03/27/what-is-electionguard/)
> "ElectionGuard is a way of checking election results are accurate, and that votes have
> not been altered, suppressed or tampered with in any way. Individual voters can see that
> their vote has been accurately recorded, and their choice has been correctly added to
> the final tally. Anyone who wishes to monitor the election can check all votes have been
> correctly tallied to produce an accurate and fair result."

Although ElectionGuard is designed to be an industrial-strength solution to help secure
traditional civic elections, it can also be used for "low stakes" forms of polling as well.
Consider using ElectionGuard anywhere the security properties provided by homomorphic encryption
could be beneficial.

## What is this project and where does it fit in?

This project is a CURRENTLY EXPERIMENTAL open source Rust implementation of ElectionGuard 2.0,
intended to serve as a reference or as production software for those wishing to incorporate
ElectionGuard into their systems.

The Rust Language was chosen for this reference implementation due to its:
- Innovative memory safety guarantees and excellent security and reliability track record
- Strong, static, well-defined, type system
- Runtime performance
- Cross platform compatibility and ability to integrate with external code defined in C
- Modern design, and

This is not the only implementation of ElectionGuard. Other projects include:

### ElectionGuard 2.0

- [ElectionGuard 2.0 in Kotlin](https://github.com/danwallach/electionguard-kotlin-multiplatform) from Dan Wallach of Rice University

### ElectionGuard 1.x

- [ElectionGuard 1.x in Python](https://github.com/microsoft/electionguard-python) [docs](https://microsoft.github.io/electionguard-python/) from Microsoft
- [ElectionGuard 1.x API in C](https://github.com/microsoft/electionguard-c) from Microsoft [No longer maintained]
- [ElectionGuard 1.x API in C#](https://github.com/microsoft/electionguard-dotnet) from Microsoft [No longer maintained]
- [ElectionGuard 1.x SDK Reference Verifier]() from Microsoft

# Documentation

## In this source repo

[README](./README.md) this document

[building](./building.md) <--- Start here

[SECURITY](./SECURITY.md) Reporting security issues

[SUPPORT](./SUPPORT.md) How to engage with developers and community

## Built from sources under ./doc

[Table of Contents](./src/target/doc/table_of_contents.html)

# This document TODO

> > This repo has been populated by an initial template to help get you started. Please
> > make sure to update the content to build a great experience for community-building.
> 
> As the maintainer of this project, please make a few updates:
> 
> - Improving this README.MD file to provide a great experience
> - Updating SUPPORT.MD with content about this project's support experience
> - Understanding the security reporting process in SECURITY.MD
> - Remove this section from the README

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
