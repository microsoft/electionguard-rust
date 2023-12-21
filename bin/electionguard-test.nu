#!/usr/bin/env nu

# watch -v bin\electionguard-test.nu {|$it| nu bin\electionguard-test.nu --release --test-hash-mismatch-warn-only --no-test --no-build-docs }

use std
use std log

# electionguard-test - End-to-end test script for ElectionGuard tests.
def main [
    --release         # Supply the --release flag to cargo commands.
    --clean           # Run cargo clean.
    --no-build        # Do not run cargo build.
    --no-check        # Do not run cargo check.
    --no-clippy       # Do not run cargo clippy.
    --no-test         # Do not run cargo test.
    --test-hash-mismatch-warn-only # Only warn, don't error, if hashes mismatch in unit tests.
    --no-build-docs   # Do not build docs.
    --erase-artifacts # Erase the artifacts directory before running electionguard.exe tests.
    --no-egtest       # Do not run electionguard.exe tests.
    --no-insecure-deterministic # Do not use the --insecure-deterministic flag.
] {
    let electionguard_root_dir = ($env.FILE_PWD | path dirname)

    std log info $"Started ($env.CURRENT_FILE | path relative-to $electionguard_root_dir)"
    std log info $"electionguard_root_dir=($electionguard_root_dir)"
    
    let electionguard_bin_dir = ($electionguard_root_dir | path join bin)
    std log info $"electionguard_bin_dir=($electionguard_bin_dir)"

    let $electionguard_artifacts_dir = $env.ELECTIONGUARD_ARTIFACTS_DIR?
    std log info $"electionguard_artifacts_dir=($electionguard_artifacts_dir)"
    if $"($electionguard_artifacts_dir)" == "" {
        std log error "Env var ELECTIONGUARD_ARTIFACTS_DIR is not set."
        exit 1
    }
    if ($electionguard_artifacts_dir | path type) != dir {
        std log error $"ELECTIONGUARD_ARTIFACTS_DIR is not a directory: ($electionguard_artifacts_dir)"
        exit 1
    }

    # Specify the election parameters.
    let election_parameters = {
        n: 5
        k: 3
        date: (date now | format date "%Y-%m-%d")
        info: $"The United Realms of Imaginaria General Election ((date now | date to-record).year)"
    }

    let $electionguard_src_dir = ($electionguard_root_dir | path join src)
    std log info $"electionguard_src_dir=($electionguard_src_dir)"
    cd $electionguard_src_dir

    # Figure the cargo profile build flag and the cargo target directory.

    let cargo_profile_build_flag = if $release { '--release' } else { null }
    let cargo_target_reldir = if $release {
        ([ target release ] | path join)
    } else {
        ([ target debug ] | path join)
    }

    let binary_name = "electionguard"
    let binary = ($cargo_target_reldir | path join $binary_name)
    log info $"binary=($binary)"

    #  Figure out RUSTFLAGS
    # 
    std log info $"Previous RUSTFLAGS: ($env.RUSTFLAGS?)"
    if $test_hash_mismatch_warn_only {
        $env.RUSTFLAGS = ($"($env.RUSTFLAGS?) --cfg test_hash_mismatch_warn_only" | str trim)
    }
    std log info $"Subsequent RUSTFLAGS: ($env.RUSTFLAGS?)"

    #  Cargo clean
    # 
    if $clean {
        run-subprocess [ cargo clean $cargo_profile_build_flag ]

        #if $target_platform == "windows" {
        #    dumpbin /imports $electionguard_exe
        #}
    }

    #  Cargo build
    # 
    if not $no_build {
        run-subprocess [ cargo build -vv $cargo_profile_build_flag ]
    }

    #  Cargo check
    # 
    if not $no_check {
        run-subprocess [ cargo check $cargo_profile_build_flag ]
    }

    #  Cargo clippy
    # 
    if not $no_clippy {
        run-subprocess [ cargo clippy $cargo_profile_build_flag ]
    }

    #  Cargo test
    # 
    if not $no_test {
        run-subprocess [
            cargo test $cargo_profile_build_flag --
            --test-threads=1 --nocapture
        ]
    }

    #  Build docs
    # 
    if not $no_build_docs {
        let build_docs = ($electionguard_bin_dir | path join build-docs.cmd)
        std log info $"build_docs: ($build_docs)"
        std log info $"env.PWD: ($env.PWD)"
        let build_docs_relto_root = ($build_docs | path relative-to $electionguard_root_dir)
        std log info $"build_docs_relto_root: ($build_docs_relto_root)"
        let build_docs = ('..' | path join $build_docs_relto_root)
        std log info $"build_docs: ($build_docs)"
        run-subprocess --delimit [
            cmd.exe /c ($build_docs)
        ]
    }

    #  Erase ELECTIONGUARD_ARTIFACTS_DIR
    #
    if $erase_artifacts {
        if ($electionguard_artifacts_dir | path exists) {
            log info $"Removing artifacts directory."
            rm -rf $electionguard_artifacts_dir
        }
    }

    #  Run ElectionGuard tests
    # 
    if not $no_egtest {
        (egtests $binary $election_parameters
            --cargo_profile_build_flag $cargo_profile_build_flag
            --electionguard_artifacts_dir $electionguard_artifacts_dir)
    }

    #  Success!
    # 
    log info "Success!"
}

def egtests [
    binary: string
    election_parameters: record<n: int, k: int, date: string, info: string>
    --cargo_profile_build_flag: string
    --electionguard_artifacts_dir: string
] {
    #  Build electionguard.exe and its dependents
    # 
    run-subprocess [
        cargo build $cargo_profile_build_flag -p electionguard
    ]

    if not ($binary | path exists) {
        log error $"ERROR: binary does not exist: ($binary)"
        exit
    }

    # 
    #  ensure ELECTIONGUARD_ARTIFACTS_DIR exists
    # 
    let electionguard_artifacts_public_dir = $electionguard_artifacts_dir | path join "public"

    if not ($electionguard_artifacts_public_dir | path exists) {
        log info $"Creating artifacts directory."
        mkdir $electionguard_artifacts_public_dir
    }

    # 
    #  Write random seed
    # 
    if not ($electionguard_artifacts_public_dir | path join "pseudorandom_seed_defeats_all_secrecy.bin" | path exists) {
        run-subprocess [ $binary write-random-seed ]
    }

    # 
    #  Verify standard parameters
    # 
    let standard_parameters_verified_file = $electionguard_artifacts_public_dir | path join "standard_parameters_verified.txt"
    if ($standard_parameters_verified_file | path exists) {
        run-subprocess [
            $binary --insecure-deterministic verify-standard-parameters
        ]

        log info $"Standard parameters: Verified! >($standard_parameters_verified_file)"
    }

    # 
    #  Write election manifest (canonical)
    # 
    if not ($electionguard_artifacts_public_dir | path join "election_manifest_canonical.bin" | path exists) {
        run-subprocess [
            $binary write-manifest --in-example --out-format canonical
        ]
    }

    # 
    #  Write election manifest (pretty)
    # 
    if not ($electionguard_artifacts_public_dir | path join "election_manifest_pretty.json" | path exists) {
        run-subprocess [ $binary write-manifest --out-format pretty ]
    }

    # 
    #  Write election parameters
    # 
    if not ($electionguard_artifacts_public_dir | path join "election_parameters.json" | path exists) {
        run-subprocess [
            $binary write-parameters
                --n $election_parameters.n
                --k $election_parameters.k
                --date $election_parameters.date
                --info $election_parameters.info
                --ballot-chaining prohibited
        ]
    }

    # 
    #  Write hashes
    # 
    if not ($electionguard_artifacts_public_dir | path join "hashes.json" | path exists) {
        run-subprocess [
            $binary --insecure-deterministic write-hashes
        ]
    }

    # 
    #  For each guardian
    #
    for $i in 1..$election_parameters.n {
        (egtest_per_guardian $binary $i
            --electionguard_artifacts_dir $electionguard_artifacts_dir
            --electionguard_artifacts_public_dir $electionguard_artifacts_public_dir)
    }

    log info ""
    log info "---- All guardians done."

    # 
    #  Write joint election public key
    # 
    if not ($electionguard_artifacts_public_dir | path join "joint_election_public_key.json" | path exists) {
        run-subprocess [
            $binary --insecure-deterministic write-joint-election-public-key
        ]
    }

    # 
    #  Write HashesExt
    # 
    if not ($electionguard_artifacts_public_dir | path join "hashes_ext.json" | path exists) {
        run-subprocess [ $binary --insecure-deterministic write-hashes-ext ]
    }

    # 
    #  Tests success!
    # 
    log info ""
    log info "ElectionGuard tests successful!"
    log info ""
    log info "Resulting artifact files:"

    ls $electionguard_artifacts_dir
}

def egtest_per_guardian [
    binary: string
    i: int
    --electionguard_artifacts_dir: string
    --electionguard_artifacts_public_dir: string
] {
    let guardian_secret_dir = $electionguard_artifacts_dir | path join $"SECRET_for_guardian_($i)"
    if not ($guardian_secret_dir | path exists) {
        mkdir $guardian_secret_dir
    }

    let guardian_secret_key_file = $guardian_secret_dir | path join $"guardian_($i).SECRET_key.json"
    let guardian_public_key_file = $electionguard_artifacts_public_dir | path join $"guardian_($i).public_key.json"
    let guardian_name = $"Guardian ($i)"

    log info ""
    log info $"---- Guardian ($i)"
    log info ""
    log info $"Secret key file: ($guardian_secret_key_file)"
    log info $"Public key file: ($guardian_public_key_file)"

    if not ($guardian_secret_key_file | path exists) {
        if ($guardian_public_key_file | path exists) {
            rm $guardian_public_key_file
        }

        run-subprocess [
            $binary --insecure-deterministic guardian-secret-key-generate --i $i --name $guardian_name
        ]

        if not ($guardian_secret_key_file | path exists) {
            log error $"ERROR: Guardian ($i) secret key file does not exist: ($guardian_secret_key_file)"
            exit 1
        }
    }

    if not ($guardian_public_key_file | path exists) {
        run-subprocess [
            $binary --insecure-deterministic guardian-secret-key-write-public-key --i $i
        ]

        if not ($guardian_public_key_file | path exists) {
            log error $"Guardian ($i) public key file does not exist: ($guardian_public_key_file)"
            exit 1
        }
    }
}

# Runs a subprocess and returns the exit code.
# Also, it errors if the exit code is non-zero.
def run-subprocess [
    --delimit
    argv: list<string>
] {
    let argv = ($argv | into string | filter {|it| not ($it | is-empty )})
    std log info $"Executing: ($argv)"

    let argv_str = ($argv | str join ' ')

    let argv_0 = $argv.0
    let argv_1_n = ($argv | skip 1)
    #std log info $"argv_0: ($argv_0)"
    #std log info $"argv_1_n: ($argv_1_n)"

    if $delimit {
        print $"vvvvvvvvvvvvvvvvvvvvvvvvvvvv ($argv_str) vvvvvvvvvvvvvvvvvvvvvvvvvvvv"
    }

    ^$argv_0 $argv_1_n

    if $delimit {
        print $"^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ($argv_str) ^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    }

    std log info $"Exit code: ($env.LAST_EXIT_CODE)"
    $env.LAST_EXIT_CODE
}
