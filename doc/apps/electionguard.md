# Application `electionguard`

## Commands and common options
```
Usage: electionguard.exe [OPTIONS] --artifacts-dir <ARTIFACTS_DIR> <COMMAND>

Commands:
  write-random-seed                     Writes a random seed file to the artifacts directory. Future commands will use this seed to make their operation deterministic
  verify-standard-parameters            Verify standard parameters. Primarily for testing
  write-manifest                        Write the election manifest to a file
  write-parameters                      Write the election parameters to a file
  write-hashes                          Write the hashes to a file
  guardian-secret-key-generate          Generate a guardian secret key
  guardian-secret-key-write-public-key  Write a guardian public key from a guardian secret key
  write-joint-election-public-key       Compute the joint election public key from the guardian public keys and write it to a file
  write-hashes-ext                      Write the extended hash to a file
  help                                  Print this message or the help of the given subcommand(s)

Options:
      --artifacts-dir <ARTIFACTS_DIR>  An existing directory for artifacts [env: ELECTIONGUARD_ARTIFACTS_DIR=C:\w\snc\eg\artifacts]
      --insecure-deterministic         Make the entire operation deterministic by using the seed data from the `artifacts/pseudorandom_seed_defeats_all_secrecy.bin` file. This is completely insecure and should only be used for testing
  -h, --help                           Print help
```

## write-random-seed
```
Writes a random seed file to the artifacts directory. Future commands will use this seed to make their operation deterministic

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-random-seed [OPTIONS]

Options:
      --overwrite
```

## verify-standard-parameters
```
Verify standard parameters. Primarily for testing

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> verify-standard-parameters [OPTIONS]

Options:
      --passes <PASSES>  [default: 1]
```

## write-manifest
```
Write the election manifest to a file

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-manifest [OPTIONS]

Options:
      --in-pretty                Use the pretty JSON election manifest file in the artifacts dir..
      --in-canonical             Use the canonical JSON election manifest file in the artifacts dir..
      --in-file <IN_FILE>        Input election manifest file. Default is the canonical JSON file in the artifacts dir
      --in-example               Use the built-in example election manifest
      --out-format <OUT_FORMAT>  Output format. Default is canonical. Unless `--out-file` is specified, the output is written to the appropriate file in the artifacts dir [default: canonical] [possible values: canonical, pretty]
      --out-file <OUT_FILE>      File to which to write the election manifest. Default is the appropriate election manifest file in the artifacts dir. If "-", write to stdout
```

## write-parameters
```
Write the election parameters to a file

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-parameters [OPTIONS] --n <N> --k <K> --date <DATE> --info <INFO>

Options:
      --n <N>                Number of guardians
      --k <K>                Decryption quorum threshold value
      --date <DATE>          Date string
      --info <INFO>
      --out-file <OUT_FILE>  File to which to write the election parameters. Default is the election parameters file in the artifacts dir. If "-", write to stdout
```

## write-hashes
```
Write the hashes to a file

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-hashes [OPTIONS]

Options:
      --out-file <OUT_FILE>  File to which to write the hashes. Default is the election parameters file in the artifacts dir. If "-", write to stdout
```

## guardian-secret-key-generate
```
Generate a guardian secret key

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> guardian-secret-key-generate [OPTIONS] --i <I>

Options:
      --i <I>
          Guardian number, 1 <= i <= n
      --name <NAME>
          Guardian's name or other short description
      --secret-key-out-file <SECRET_KEY_OUT_FILE>
          File to which to write the guardian's secret key. Default is in the guardian's dir under the artifacts dir. If "-", write to stdout
```

## guardian-secret-key-write-public-key
```
Write a guardian public key from a guardian secret key

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> guardian-secret-key-write-public-key [OPTIONS]

Options:
      --i <I>
          Guardian number, 1 <= i <= n
      --secret-key-in <SECRET_KEY_IN>
          File containing the guardian's secret key. Default is to look in the artifacts dir, if --i is provided
      --public-key-out <PUBLIC_KEY_OUT>
          File to which to write the guardian's public key. Default is in the artifacts dir, based on the guardian number from the secret key file. If "-", write to stdout
```

## write-joint-election-public-key
```
Compute the joint election public key from the guardian public keys and write it to a file

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-joint-election-public-key [OPTIONS]

Options:
      --out-file <OUT_FILE>  File to which to write the election public key. Default is in the artifacts dir. If "-", write to stdout
```

## write-hashes-ext
```
Write the extended hash to a file

Usage: electionguard.exe --artifacts-dir <ARTIFACTS_DIR> write-hashes-ext [OPTIONS]

Options:
      --out-file <OUT_FILE>  File to which to write the extended. Default is in the artifacts dir. If "-", write to stdout
```
