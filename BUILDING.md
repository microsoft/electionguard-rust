# Building

Building the core components of this reference implementation requires only:

* The Rust language basic toolchain, and

* [Nushell](https://nushell.sh) for some tasks such as integration tests
and building the documentation. It is *not* a software dependency of the
actual ElectionGuard reference implementation.

## Terminology

The Rust language documentation uses these terms in a specific way:

* ***host*** - the system that the compiler (i.e., rustc) runs on.
* ***target*** - the system that the built code (e.g., `electionguard.exe``) will run on.

Although this definition of 'host' is different from that used in other contexts
(cf. [htonl()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/htonl.html)),
it makes complete sense from a compiler writer's perspective.

## Decisions

### Rust toolchain release channel

The Rust toolchain comes in two flavors: `stable` and `nightly`. For production use,
you probably want to stick with `stable`.

All supported functionality requires only the `stable` toolchain.

But it may be that some tests and experimental features might require `nightly`.

### Windows targets

When targeting Windows (e.g., a developer on Windows building to run locally) there
are multiple options of ABI: `MSVC` and `MinGW`. The native, Visual Studio-based, `MSVC`
ABI is recommended, if for no reason other than it is likely to have been tested more.

See [Windows - The rustup book](https://rust-lang.github.io/rustup/installation/windows.html)
for more information.

## Prerequisites

### C compiler for target platform

The Rust build system relies on having a C language compiler (or at least the linker
and libraries) appropriate for the target platform.

If you're targeting MS Windows, 
https://rust-lang.github.io/rustup/installation/windows.html

### Rust language build environment

[Install Rust](https://www.rust-lang.org/tools/install)

https://rust-lang.github.io/rustup/installation/index.html

### Nushell

[Nushell](https://nushell.sh) is a Rust-based scripting environment used for orchestrating multi-step tests, building the
API documentation, etc. It is *not* a software dependency of ElectionGuard reference implementation.

[Documentation](https://nushell.sh)

[Documentation](https://github.com/nushell/nushell)

There are several ways to install it from pre-built packages.

However, 

## Configuration

