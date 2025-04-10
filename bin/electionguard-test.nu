#!/usr/bin/env nu

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
    --no-build-docs   # Do not build docs.
    --erase-artifacts # Erase the artifacts directory before running electionguard.exe tests.
    --no-egtest       # Do not run electionguard.exe tests.
    --no-jsonschema   # Do not validate files against JSON schema.
    --no-insecure-deterministic # Do not use the --insecure-deterministic flag.
    --dump-imports    # Dump the imports of the resulting binary (currently windows only)
    --num-guardians: int = 5 # Number of guardians to use in test (default 5)
    --num-quorum: int = 3    # Number of guardians required for quorum (default 3)
    --num-ballots: int = 5   # Number of ballots to use in test (default 5)
] {
    figure_eg_top_dir
    std log info $"Started ($env.CURRENT_FILE | path relative-to (eg_top_dir))"
    std log info $"Checkout top dir: (eg_top_dir)"

    figure_artifacts_dir
    std log info $"Artifacts dir: (artifacts_dir)"

    if not $no_jsonschema {
        figure_jsonschema_command
        figure_jsonschema_dir
    }

    let electionguard_bin_dir = (eg_top_dir | path join bin)
    std log info $"electionguard_bin_dir=($electionguard_bin_dir)"

    # Specify the election parameters.
    let election_parameters = {
        n: $num_guardians
        k: $num_quorum
        date: (date now | format date "%Y-%m-%d")
        info: $"The United Realms of Imaginaria General Election ((date now | date to-record).year)"
    }

    let $electionguard_src_dir = (eg_top_dir | path join src)
    std log info $"electionguard_src_dir=($electionguard_src_dir)"
    cd $electionguard_src_dir

    # Figure the cargo profile build flag and the cargo target directory.

    let cargo_profile_build_flag = if $release { '--release' } else { null }
    let rel_deb: string = if $release { 'release' } else { 'debug' }
    let cargo_target_dir: string = ([
            $electionguard_src_dir,
            'target',
            $rel_deb
        ] | path join)

    figure_eg_exe $cargo_target_dir

    #  Figure out RUSTFLAGS
    #
    std log info $"Previous RUSTFLAGS: ($env.RUSTFLAGS? | default "")"
    let xxx_some_cfg_setting = false
    if $xxx_some_cfg_setting {
        $env.RUSTFLAGS = ($"($env.RUSTFLAGS? | default "") --cfg xxx_some_cfg_setting" | str trim)
    }
    std log info $"Subsequent RUSTFLAGS: ($env.RUSTFLAGS? | default "")"

    #  Cargo clean
    #
    if $clean {
        run-subprocess --delimit [ cargo clean $cargo_profile_build_flag ]
    }

    #  Erase ELECTIONGUARD_ARTIFACTS_DIR
    #
    if $erase_artifacts {
        if (artifacts_dir | path exists) {
            log info $"Removing artifacts directory."
            rm -rf (artifacts_dir)
        }
    }
    if not (artifacts_dir | path exists) {
        log info $"Creating artifacts directory."
        mkdir (artifacts_dir)
    }

    #  Cargo build
    #
    let cargo_build_flag_vv = null
    if not $no_build {
        run-subprocess --delimit [ cargo build $cargo_build_flag_vv $cargo_profile_build_flag ]

        if $dump_imports and (target_is_windows) {
            dumpbin /imports (eg_exe)
        }
    }

    #  Cargo check
    #
    if not $no_check {
        run-subprocess --delimit [ cargo check $cargo_profile_build_flag ]
    }

    #  Cargo clippy
    #
    if not $no_clippy {
        run-subprocess --delimit [ cargo clippy $cargo_profile_build_flag ]
    }

    #  Cargo test
    #
    if not $no_test {
        run-subprocess --delimit [
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
        let build_docs_relto_root = ($build_docs | path relative-to (eg_top_dir))
        std log info $"build_docs_relto_root: ($build_docs_relto_root)"
        let build_docs = ('..' | path join $build_docs_relto_root)
        std log info $"build_docs: ($build_docs)"
        run-subprocess --delimit [
            cmd.exe /c ($build_docs)
        ]
    }

    #  Run ElectionGuard tests
    #
    if not $no_egtest {
        (egtests $election_parameters
            --cargo_profile_build_flag $cargo_profile_build_flag
            --num-ballots=$num_ballots
            --no-jsonschema=$no_jsonschema )
    }

    #  Success!
    #
    log info "Success!"
}

def --env figure_eg_top_dir [] {
    let dir = ($env.FILE_PWD | path dirname)
    $env._eg_top_dir = $dir
}

def eg_top_dir [] -> string {
    $env._eg_top_dir
}

def --env figure_artifacts_dir [] {
    let dir: string = ($env.ELECTIONGUARD_ARTIFACTS_DIR? | default "")
    std log info $"ELECTIONGUARD_ARTIFACTS_DIR: ($dir)"
    if $dir == "" {
        std log error "Env var ELECTIONGUARD_ARTIFACTS_DIR is not set."
        exit 1
    }

    $env._eg_artifacts_dir = $dir
}

def artifacts_dir [] -> string {
    let dir = $env._eg_artifacts_dir

    if ($dir | path exists) {
        let type = $dir | path type;
        if $type != dir {
            std log error $"ELECTIONGUARD_ARTIFACTS_DIR exists \(\"($dir)\"\), but it's a '($type)', not a directory."
            exit 1
        }
    } else {
        log info $"Creating artifacts directory: ($dir)"
        mkdir $dir
    }

    $env._eg_artifacts_dir
}

def artifacts_public_dir [] -> string {
    let dir = artifacts_dir | path join "public"
    if ($dir | path exists) {
        let type = $dir | path type;
        if $type != dir {
            std log error $"Artifacts public dir exists \(\"($dir)\"\), but it's a '($type)', not a directory."
            exit 1
        }
    } else {
        log info $"Creating artifacts public dir: ($dir)"
        mkdir $dir
    }

    $dir
}

def target_is_windows [] -> bool {
    (sys host).name =~ '(?i)^\s*windows\b.*'
}

def --env figure_eg_exe [$cargo_target_dir] {
    mut eg_exe_name = "electionguard"
    if (target_is_windows) {
        $eg_exe_name = ([$eg_exe_name, ".exe"] | str join)
    }

    $env._eg_exe = ($cargo_target_dir | path join $eg_exe_name)

    log info $"electionguard executable: ($env._eg_exe)"
}

def eg_exe [] -> string {
    $env._eg_exe
}

def --env figure_jsonschema_command [] {
    mut jsonschema_command_name = "jsonschema"

    $env._jsonschema_command = $jsonschema_command_name

    log info $"jsonschema command: ($env._jsonschema_command)"

    let exit_code = run-subprocess --delimit [
        (jsonschema_command) --version
    ]
    if $exit_code != 0 {
        log error $"ERROR: The jsonschema command '($env._jsonschema_command)' isn't working. Supply the --no-jsonschema flag to skip it."
        exit 1
    }
}

def jsonschema_command [] -> string {
    $env._jsonschema_command
}

def --env figure_jsonschema_dir [] {
    let dir = (eg_top_dir | path join "doc/specs/ElectionGuard_2.0_jsonschema")

    $env._eg_jsonschema_dir = $dir

    std log info $"jsonschema dir: ($env._eg_jsonschema_dir)"
}

def eg_jsonschema_dir [] -> string {
    $env._eg_jsonschema_dir
}

def egtests [
    election_parameters: record<n: int, k: int, date: string, info: string>
    --cargo_profile_build_flag: string
    --no-jsonschema
    --num-ballots: int
] {
    std log info $"num_ballots=($num_ballots)"

    #  Build electionguard.exe and its dependents
    #
    run-subprocess --delimit [
        cargo build $cargo_profile_build_flag -p electionguard
    ]

    if not (eg_exe | path exists) {
        log error $"ERROR: executable does not exist: (eg_exe)"
        exit
    }

    #
    #  Write insecure deterministic seed data file
    #
    if not (artifacts_public_dir | path join "insecure_deterministic_seed_data.bin" | path exists) {
        run-subprocess --delimit [ (eg_exe) write-insecure-deterministic-seed-data ]
    }

    #
    #  Write election parameters
    #
    let election_parameters_json_file = artifacts_public_dir | path join "election_parameters.json"
    if not ($election_parameters_json_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) write-parameters
                --n $election_parameters.n
                --k $election_parameters.k
                --date $election_parameters.date
                --info $election_parameters.info
                --ballot-chaining prohibited
        ]

        if not ($election_parameters_json_file | path exists) {
            log error $"ERROR: Election parameters file does not exist: ($election_parameters_json_file)"
            exit 1
        }
    }

    if not $no_jsonschema {
        validate-jsonschema --json-file $election_parameters_json_file --schema-file 'election_parameters.json'
    }

    #
    #  Verify standard parameters
    #
    let standard_parameters_verified_file = artifacts_public_dir | path join "standard_parameters_verified.txt"
    if not ($standard_parameters_verified_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic verify-standard-parameters
        ]

        log info $"Standard parameters: Verified! >($standard_parameters_verified_file)"
    }

    #
    #  Write election manifest (canonical and pretty), then validate them with the schema
    #

    let election_manifest_pretty_json_file = artifacts_public_dir | path join "election_manifest.json"
    let election_manifest_canonical_json_file = artifacts_public_dir | path join "election_manifest_canonical.bin"

    if not ($election_manifest_pretty_json_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) write-manifest --in-example --out-format pretty
        ]

        if not ($election_manifest_pretty_json_file | path exists) {
            log error $"ERROR: Election manifest \(pretty) file does not exist: ($election_manifest_pretty_json_file)"
            exit 1
        }
    }

    if not ($election_manifest_canonical_json_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) write-manifest --in-example --out-format canonical
        ]

        if not ($election_manifest_canonical_json_file | path exists) {
            log error $"ERROR: Election manifest \(canonical) file does not exist: ($election_manifest_canonical_json_file)"
            exit 1
        }
    }

    if not $no_jsonschema {
        validate-jsonschema --json-file $election_manifest_pretty_json_file --schema-file 'election_manifest.json'
        validate-jsonschema --json-file $election_manifest_canonical_json_file --schema-file 'election_manifest.json'
    }

    #
    #  Write hashes
    #
    let hashes_json_file = artifacts_public_dir | path join "hashes.json"
    if not ($hashes_json_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic write-hashes
        ]

        if not ($hashes_json_file | path exists) {
            log error $"ERROR: Hashes .json file does not exist: ($hashes_json_file)"
            exit 1
        }
    }

    if not $no_jsonschema {
        validate-jsonschema --json-file $hashes_json_file --schema-file 'hashes.json'
    }

    #
    #  For each guardian
    #
    for $i in 1..$election_parameters.n {
        egtest_per_guardian $i --no-jsonschema=$no_jsonschema
    }

    log info ""
    log info "---- All guardians done."

    #
    #  Write joint election public key
    #
    let joint_election_public_key_json_file = artifacts_public_dir | path join "joint_election_public_key.json"
    if not ($joint_election_public_key_json_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic write-joint-election-public-key
        ]
    }

    if not ($joint_election_public_key_json_file | path exists) {
        log error $"ERROR: Joint election public key .json file does not exist: ($joint_election_public_key_json_file)"
        exit 1
    }

    if not $no_jsonschema {
        validate-jsonschema --json-file $joint_election_public_key_json_file --schema-file 'joint_election_public_key.json'
    }

    #
    #  Write HashesExt
    #
    let hashes_ext_json_file = artifacts_public_dir | path join "hashes_ext.json"
    if not ($hashes_ext_json_file | path exists) {
        run-subprocess --delimit [ (eg_exe) --insecure-deterministic write-hashes-ext ]
    }

    if not ($hashes_ext_json_file | path exists) {
        log error $"ERROR: Hashes ext .json file does not exist: ($hashes_ext_json_file)"
        exit 1
    }

    if not $no_jsonschema {
        validate-jsonschema --json-file $hashes_ext_json_file --schema-file 'hashes_ext.json'
    }

    #
    #  Write PreVotingData
    #
    let pre_voting_data_json_file = artifacts_public_dir | path join "pre_voting_data.json"
    if not ($pre_voting_data_json_file | path exists) {
        run-subprocess --delimit [ (eg_exe) --insecure-deterministic write-pre-voting-data ]
    }

    if not ($pre_voting_data_json_file | path exists) {
        log error $"ERROR: Hashes ext .json file does not exist: ($pre_voting_data_json_file)"
        exit 1
    }

    #
    #  Write GeneratedTestDataVoterSelections
    #

    for $i in 1..$num_ballots {
        egtest_per_random_voter $i --no-jsonschema=$no_jsonschema
    }

    #
    #  Tests success!
    #
    log info ""
    log info "ElectionGuard tests successful!"
    log info ""
    log info "Resulting artifact files:"
    log_artifact_files
}

def log_artifact_files [] {
    cd (artifacts_dir)
    let cnt = glob -D **/* | reduce --fold 0 { |it, acc|
        let fn = ($it | path relative-to (artifacts_dir))
        let n = $acc | fill -a right -w 3
        log info $"[($n) ] ($fn)"
        $acc + 1
    }
    log info $"($cnt) artifact files."
    cd -
}

def egtest_per_guardian [
    i: int
    --no-jsonschema
] {
    let guardian_secret_dir = (artifacts_dir) | path join $"SECRET_for_guardian_($i)"
    if not ($guardian_secret_dir | path exists) {
        mkdir $guardian_secret_dir
    }

    let guardian_secret_key_file = $guardian_secret_dir | path join $"guardian_($i).SECRET_key.json"
    let guardian_public_key_file = artifacts_public_dir | path join $"guardian_($i).public_key.json"
    let guardian_public_key_canonical_file = artifacts_public_dir | path join $"guardian_($i).public_key_canonical.bin"
    let guardian_name = $"Guardian ($i)"

    log info ""
    log info $"---- Guardian ($i)"
    log info ""
    log info $"Secret key file: ($guardian_secret_key_file)"
    log info $"Public key file: ($guardian_public_key_file)"
    log info $"Public key \(canonical\) file: ($guardian_public_key_canonical_file)"

    if not ($guardian_secret_key_file | path exists) {
        if ($guardian_public_key_file | path exists) {
            rm $guardian_public_key_file
        }

        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic guardian-secret-key-generate --i $i --name $guardian_name
        ]

        if not ($guardian_secret_key_file | path exists) {
            log error $"ERROR: Guardian ($i) secret key file does not exist: ($guardian_secret_key_file)"
            exit 1
        }

        if not $no_jsonschema {
            validate-jsonschema --json-file $guardian_secret_key_file --schema-file 'guardian_secret_key.json'
        }
    }

    if not ($guardian_public_key_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic guardian-secret-key-write-public-key --i $i
        ]

        if not ($guardian_public_key_file | path exists) {
            log error $"Guardian ($i) public key file does not exist: ($guardian_public_key_file)"
            exit 1
        }

        if not $no_jsonschema {
            validate-jsonschema --json-file $guardian_public_key_file --schema-file 'guardian_public_key.json'
        }
    }

    if not ($guardian_public_key_canonical_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic guardian-secret-key-write-public-key --i $i --canonical
        ]

        if not ($guardian_public_key_canonical_file | path exists) {
            log error $"Guardian ($i) public key file \(canonical\) does not exist: ($guardian_public_key_canonical_file)"
            exit 1
        }
        
        if not $no_jsonschema {
            validate-jsonschema --json-file $guardian_public_key_canonical_file --schema-file 'guardian_public_key.json'
        }
    }
}

def egtest_per_random_voter [
    i: int
    --no-jsonschema
] {
    let random_voter_selections_dir = (artifacts_dir) | path join "random_voter_selections"
    if not ($random_voter_selections_dir | path exists) {
        mkdir $random_voter_selections_dir
    }

    let voter_selections_file = $random_voter_selections_dir | path join $"random_($i).voter_selections.json"
    let random_voter_name = $"Random Voter ($i)"

    log info ""
    log info $"---- ($random_voter_name)"
    log info ""
    log info $"Random voter selections file: ($voter_selections_file)"

    if not ($voter_selections_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic generate-random-voter-selections --seed $i --out-file $voter_selections_file
        ]

        if not $no_jsonschema {
            validate-jsonschema --json-file $voter_selections_file --schema-file 'voter_selections.json'
        }
    }

    let ballots_dir = (artifacts_dir) | path join "ballots"
    if not ($ballots_dir | path exists) {
        mkdir $ballots_dir
    }

    let ballot_file = $ballots_dir | path join $"ballots_($i).voter_selections.json"

    log info $"Ballot file: ($ballot_file)"

    if not ($voter_selections_file | path exists) {
        run-subprocess --delimit [
            (eg_exe) --insecure-deterministic create-ballot-from-voter-selections --voter-selections $voter_selections_file --out-file $ballot_file
        ]

        if not $no_jsonschema {
            validate-jsonschema --json-file $ballot_file --schema-file 'ballot.json'
        }
    }
}

# Validates a json file against a json schema.
def validate-jsonschema [
    --json-file: string
    --schema-file: string # relative to eg_jsonschema_dir
] {
    run-subprocess --delimit [
        (jsonschema_command) -i $json_file (eg_jsonschema_dir | path join $schema_file)
    ]
}

# Runs a subprocess and returns the exit code.
# Also, it errors if the exit code is non-zero.
def run-subprocess [
    --delimit
    argv: list<any>
] {
    let argv = $argv | each {|it| $it | into string} | filter {|it| not ($it | is-empty )}
    std log info $"Executing: ($argv)"

    let argv_str = ($argv | str join ' ')

    let argv_0 = $argv.0
    let argv_1_n = ($argv | skip 1)
    #std log info $"argv_0: ($argv_0)"
    #std log info $"argv_1_n: ($argv_1_n)"

    if $delimit {
        print $"vvvvvvvvvvvvvvvvvvvvvvvvvvvv ($argv_str) vvvvvvvvvvvvvvvvvvvvvvvvvvvv"
    }

    ^$argv_0 ...$argv_1_n

    if $delimit {
        print $"^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ($argv_str) ^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    }

    std log info $"Exit code: ($env.LAST_EXIT_CODE)"
    $env.LAST_EXIT_CODE
}
