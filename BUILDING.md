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

All supported functionality requires only the `stable` toolchain, but it may be that
some tests and experimental features might require `nightly`.

### Windows targets

When targeting Windows (e.g., a developer on Windows building to run locally) there
are multiple options of ABI: `MSVC` and `MinGW`. The native, Visual Studio-based, `MSVC`
ABI is recommended, if for no reason other than it is likely to have been tested more
with this codebase.

See [Windows - The rustup book](https://rust-lang.github.io/rustup/installation/windows.html)
for more information.

## Prerequisites

### C compiler for target platform

The Rust build system relies on having a C language compiler (or at least the linker
and libraries) appropriate for the target platform.

Again, if you're targeting MS Windows, see
[Windows - The rustup book](https://rust-lang.github.io/rustup/installation/windows.html)
for more information.

### Rust language build environment

[Install Rust](https://www.rust-lang.org/tools/install)

https://rust-lang.github.io/rustup/installation/index.html

### Nushell

[Nushell](https://nushell.sh) is a Rust-based scripting environment used for orchestrating multi-step tests, building the
API documentation, etc. It is *not* a software dependency of ElectionGuard reference implementation.

Main site: [nushell.sh](https://nushell.sh)

[Github](https://github.com/nushell/nushell)

There are several ways to install it from pre-built packages, but one reason it was chosen was
for the simple installation process for those who already have a Rust toolchain:
```
cargo install nu
```

### (Totally optional) Insta cargo extension

Some unit tests are managed by the excellent crate [`insta`](https://crates.io/crates/insta).

Homepage: [insta.rs](https://insta.rs/).

If you expect to be developing tests, installing the `cargo` extension is recommended:
```
cargo install cargo-insta
```

But this just a convenience and is not required.

## Configuration

TODO

## Build with cargo

```
cd src
cargo build
```

## Integration test 

```
cd src
..\bin\electionguard-test.cmd --release --test-hash-mismatch-warn-only --erase-artifacts --clean
```
