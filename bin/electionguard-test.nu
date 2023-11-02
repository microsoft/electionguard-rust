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

    let electionguard_exe = ($cargo_target_reldir | path join electionguard.exe)
    std log info $"electionguard_exe=($electionguard_exe)"

    #  Figure out RUSTFLAGS
    # 
    std log info $"Previous RUSTFLAGS: ($env.RUSTFLAGS?)"
    if $test_hash_mismatch_warn_only {
        let-env RUSTFLAGS = ($"($env.RUSTFLAGS?) --cfg test_hash_mismatch_warn_only" | str trim)
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
        # if "%clarg_erase_artifacts%" EQU "0" goto :skip_erase_artifacts
        # if not exist "%ELECTIONGUARD_ARTIFACTS_DIR%" goto :skip_erase_artifacts
        # echo.
        # echo Removing artifacts directory.
        # rmdir /s /q "%ELECTIONGUARD_ARTIFACTS_DIR%"
    }

    #  Run ElectionGuard tests
    # 
    if not $no_egtest {
        egtests
    }

    #  Success!
    # 
    log info "Success!"
}

def ensure_artifacts_dir [] {
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%" goto :skip_create_artifacts_dir
    # echo.
    # echo Creating artifacts directory.
    # mkdir "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%"
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_create_artifacts_dir
}

def egtests [] {
    #  Build electionguard.exe and its dependents
    # 
    # cargo build%cargo_profile_build_flag% -p electionguard
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # 
    # if not exist "%electionguard_exe%" (
    #     echo ERROR: electionguard.exe does not exist: %electionguard_exe%
    #     exit /b 1
    # )
    # 
    #  ensure ELECTIONGUARD_ARTIFACTS_DIR exists
    # 
    # call :sub_ensure_artifacts_dir
    # 
    #  Write random seed
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\pseudorandom_seed_defeats_all_secrecy.bin" goto :skip_write_random_seed
    # %electionguard_exe% write-random-seed
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_random_seed
    # 
    #  Verify standard parameters
    # 
    # (set standard_parameters_verified_file="%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\standard_parameters_verified.txt")
    # 
    # if exist "%standard_parameters_verified_file%" goto :skip_verify_standard_parameters
    # %electionguard_exe% --insecure-deterministic verify-standard-parameters
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # 
    # echo Standard parameters: Verified! >"%standard_parameters_verified_file%"
    # 
    # :skip_verify_standard_parameters
    # 
    #  Write election manifest (canonical)
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\election_manifest_canonical.bin" goto :skip_write_manifest_canonical
    # %electionguard_exe% write-manifest --in-example --out-format canonical
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_manifest_canonical
    # 
    #  Write election manifest (pretty)
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\election_manifest_pretty.json" goto :skip_write_manifest_pretty
    # %electionguard_exe% write-manifest --out-format pretty
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_manifest_pretty
    # 
    #  Write election parameters
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\election_parameters.json" goto :skip_write_parameters
    # %electionguard_exe% write-parameters --n %eg_n% --k %eg_k% --date "%eg_date%" --info "%eg_info%"
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_parameters
    # 
    #  Write hashes
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\hashes.json" goto :skip_write_hashes
    # %electionguard_exe% --insecure-deterministic write-hashes
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_hashes
    # 
    #  For each guardian
    # 
    # for /L %%N in (1, 1, %eg_n%) do call :sub_egtest_per_guardian %%N
    # echo.
    # echo ---- All guardians done.
    # 
    #  Write joint election public key
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\joint_election_public_key.json" goto :skip_write_joint_election_public_key
    # %electionguard_exe% --insecure-deterministic write-joint-election-public-key
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_joint_election_public_key
    # 
    #  Write HashesExt
    # 
    # if exist "%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\hashes_ext.json" goto :skip_write_hashes_ext
    # %electionguard_exe% --insecure-deterministic write-hashes-ext
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_write_hashes_ext
    # 
    #  Tests success!
    # 
    # echo.
    # echo ElectionGuard tests successful!
    # echo.
    # echo Resulting artifact files:
    # dir "%ELECTIONGUARD_ARTIFACTS_DIR%" /s /b
}

# rem ======================================================= Subroutine: ElectionGuard tests - per guardian actions
def sub_egtest_per_guardian [] {
    # set /a "i=%1"
    # 
    # (set guardian_secret_dir=%ELECTIONGUARD_ARTIFACTS_DIR%\SECRET_for_guardian_%i%)
    # 
    # if exist "%guardian_secret_dir%" goto :skip_create_guardian_secret_dir
    # mkdir "%guardian_secret_dir%"
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # :skip_create_guardian_secret_dir
    # 
    # (set guardian_secret_key_file=%guardian_secret_dir%\guardian_%i%.SECRET_key.json)
    # (set guardian_public_key_file=%ELECTIONGUARD_ARTIFACTS_PUBLIC_DIR%\guardian_%i%.public_key.json)
    # (set guardian_name=Guardian %i%)
    # 
    # echo.
    # echo ---- Guardian %i%
    # echo.
    # echo Secret key file: %guardian_secret_key_file%
    # echo Public key file: %guardian_public_key_file%
    # 
    # if exist "%guardian_secret_key_file%" goto :skip_generate_secret_key
    # 
    # if exist "%guardian_public_key_file%" (
    #     erase "%guardian_public_key_file%"
    # 
    #     if "%ERRORLEVEL%" NEQ "0" exit /b
    # )
    # 
    # %electionguard_exe% --insecure-deterministic guardian-secret-key-generate --i %i% --name "%guardian_name%"
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # if not exist "%guardian_secret_key_file%" (
    #     echo ERROR: Guardian %i% secret key file does not exist: %guardian_secret_key_file%
    #     exit /b 1
    # )
    # :skip_generate_secret_key
    # 
    # if exist "%guardian_public_key_file%" goto :skip_writing_public_key
    # %electionguard_exe% --insecure-deterministic guardian-secret-key-write-public-key --i %i%
    # if "%ERRORLEVEL%" NEQ "0" exit /b
    # 
    # if not exist "%guardian_public_key_file%" (
    #     echo ERROR: Guardian %i% public key file does not exist: %guardian_public_key_file%
    #     exit /b 1
    # )
    # :skip_writing_public_key
    # 
    # goto :skip_printing_public_key
    # echo.
    # echo vvvvvvvvvvvvvv Guardian %i% "%guardian_name%" public key vvvvvvvvvvvvvv
    # type %guardian_public_key_file%
    # echo ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Guardian %i% "%guardian_name%" public key ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # :skip_printing_public_key
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
