@echo off
setlocal enableextensions enabledelayedexpansion
(set errorlevel=)

rem ----- Specify the election parameters.

set /a eg_n=5
set /a eg_k=3
(set eg_date=2023-06-13)
(set eg_info=The United Realms of Imaginaria General Election 2023)

rem ----- Handle the command line arguments

set /a clarg_help=0
set /a clarg_release=0
set /a clarg_clean=0
set /a clarg_check=1
set /a clarg_clippy=1
set /a clarg_test=1
set /a clarg_erase_artifacts=0
set /a clarg_egtest=1

:more_cmdline_args

if "_%1" EQU "_" (
    goto :no_more_cmdline_args
)
if "%1" EQU "--help" (
    set /a clarg_help=1
    goto :no_more_cmdline_args
)
if "%1" EQU "--release" (
    set /a clarg_release=1
    goto :next_cmdline_arg
)
if "%1" EQU "--clean" (
    set /a clarg_clean=1
    goto :next_cmdline_arg
)
if "%1" EQU "--no-check" (
    set /a clarg_check=0
    goto :next_cmdline_arg
)
if "%1" EQU "--no-clippy" (
    set /a clarg_clippy=0
    goto :next_cmdline_arg
)
if "%1" EQU "--no-test" (
    set /a clarg_test=0
    goto :next_cmdline_arg
)
if "%1" EQU "--erase-artifacts" (
    set /a clarg_erase_artifacts=1
    goto :next_cmdline_arg
)
if "%1" EQU "--no-egtest" (
    set /a clarg_egtest=0
    goto :next_cmdline_arg
)
echo ERROR: Unknown command line argument: %1
exit /b 1

:next_cmdline_arg
shift /1
goto :more_cmdline_args

:no_more_cmdline_args

rem ----- Handle the --help command

if "%clarg_help%" NEQ "0" (
    echo Usage:
    echo     electionguard-test.cmd --help
    echo.
    echo     electionguard-test.cmd [args]
    echo         --release: Supply the --release flag to cargo commands.
    echo         --clean: Clean the cargo build directory before building electionguard.exe.
    echo         --no-check: Do not run cargo check.
    echo         --no-clippy: Do not run cargo clippy.
    echo         --no-test: Do not run cargo test.
    echo         --erase-artifacts: Erase the artifacts directory before running electionguard.exe tests.
    echo         --no-egtest: Do not run electionguard.exe tests.
    exit /b 0
)

rem ----- Figure the full path to directory containing this script.

(set this_script_dir=%~dp0)
(set this_script_dir=%this_script_dir:~0,-1%)
echo this_script_dir=%this_script_dir%

rem ----- Check the ELECTIONGUARD_ARTIFACTS_DIR

if "_%ELECTIONGUARD_ARTIFACTS_DIR%" EQU "_" (
    echo ERROR: ELECTIONGUARD_ARTIFACTS_DIR is not set.
    exit /b 1
)

(set guardians_dir=%ELECTIONGUARD_ARTIFACTS_DIR%\guardians)
echo guardians_dir=%guardians_dir%

rem ----- Change to the directory from which we should run cargo.

for %%F in (%this_script_dir%\..\src\xxx) do (set electionguard_src_dir=%%~dpF)
(set electionguard_src_dir=%electionguard_src_dir:~0,-1%)
echo electionguard_src_dir=%electionguard_src_dir%

echo.
echo cd /d "%electionguard_src_dir%"
cd /d "%electionguard_src_dir%"
if "%ERRORLEVEL%" NEQ "0" exit /b

rem ---- Figure the cargo profile build flag and the cargo target directory.

(set cargo_profile_build_flag=)
if "%clarg_release%" NEQ "0" (
    (set cargo_profile_build_flag= --release)
    rem (set cargo_target_reldir=%electionguard_src_dir%\target\release)
    (set cargo_target_reldir=target\release)
) else (
    (set cargo_profile_build_flag=)
    rem (set cargo_target_reldir=%electionguard_src_dir%\target\debug)
    (set cargo_target_reldir=target\debug)
)

(set electionguard_exe=%cargo_target_reldir%\electionguard.exe)

rem ---- Cargo clean

if "%clarg_clean%" EQU "0" goto :skip_cargo_clean
echo.
echo cargo clean%cargo_profile_build_flag%
cargo clean%cargo_profile_build_flag%
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_cargo_clean

rem ---- Cargo check

if "%clarg_check%" EQU "0" goto :skip_cargo_check
echo.
echo cargo check%cargo_profile_build_flag%
cargo check%cargo_profile_build_flag%
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_cargo_check

rem ---- Cargo clippy

if "%clarg_clippy%" EQU "0" goto :skip_cargo_clippy
echo.
echo cargo clippy%cargo_profile_build_flag%
cargo clippy%cargo_profile_build_flag%
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_cargo_clippy

rem ---- Cargo test

if "%clarg_test%" EQU "0" goto :skip_cargo_test
echo.
echo cargo test%cargo_profile_build_flag% -- --test-threads=1 --nocapture
cargo test%cargo_profile_build_flag% -- --test-threads=1 --nocapture
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_cargo_test

rem ---- Erase ELECTIONGUARD_ARTIFACTS_DIR

if "%clarg_erase_artifacts%" EQU "0" goto :skip_erase_artifacts
if not exist "%ELECTIONGUARD_ARTIFACTS_DIR%" goto :skip_erase_artifacts
echo.
echo Removing artifacts directory.
echo rmdir /s /q "%ELECTIONGUARD_ARTIFACTS_DIR%"
rmdir /s /q "%ELECTIONGUARD_ARTIFACTS_DIR%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_erase_artifacts

rem ---- Run ElectionGuard tests

if "%clarg_egtest%" NEQ "0" call :sub_egtest

rem ---- Success!

exit /b 0

rem ======================================================= Subroutine: ElectionGuard tests
:sub_ensure_artifacts_dir

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%" goto :skip_create_artifacts_dir
echo.
echo Creating artifacts directory.
echo mkdir "%ELECTIONGUARD_ARTIFACTS_DIR%"
mkdir "%ELECTIONGUARD_ARTIFACTS_DIR%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_create_artifacts_dir

exit /b 0 & rem ------- end of :sub_ensure_artifacts_dir

:sub_egtest & rem ----------------------- subroutine: ElectionGuard tests

rem ---- Build electionguard.exe and its dependents

echo.
echo cargo build%cargo_profile_build_flag% -p electionguard
cargo build%cargo_profile_build_flag% -p electionguard
if "%ERRORLEVEL%" NEQ "0" exit /b

if not exist "%electionguard_exe%" (
    echo ERROR: electionguard.exe does not exist: %electionguard_exe%
    exit /b 1
)

rem ---- ensure ELECTIONGUARD_ARTIFACTS_DIR exists

call :sub_ensure_artifacts_dir

rem ---- Write random seed

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\pseudorandom_seed_defeats_all_secrecy.bin" goto :skip_write_random_seed
echo.
echo %electionguard_exe% write-random-seed
%electionguard_exe% write-random-seed
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_write_random_seed

rem ---- Verify standard parameters

(set standard_parameters_verified_file="%ELECTIONGUARD_ARTIFACTS_DIR%\standard_parameters_verified.txt")

if exist "%standard_parameters_verified_file%" goto :skip_verify_standard_parameters
echo.
echo %electionguard_exe% --insecure-deterministic verify-standard-parameters
%electionguard_exe% --insecure-deterministic verify-standard-parameters
if "%ERRORLEVEL%" NEQ "0" exit /b

echo Standard parameters: Verified! >"%standard_parameters_verified_file%"

:skip_verify_standard_parameters

rem ---- Write election manifest (canonical)

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_manifest_canonical.bin" goto :skip_write_manifest_canonical
echo.
echo %electionguard_exe% write-manifest --in-example --out-format canonical
%electionguard_exe% write-manifest --in-example --out-format canonical
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_write_manifest_canonical

rem ---- Write election manifest (pretty)

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_manifest_pretty.json" goto :skip_write_manifest_pretty
echo.
echo %electionguard_exe% write-manifest --out-format pretty
%electionguard_exe% write-manifest --out-format pretty
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_write_manifest_pretty

rem ---- Write election parameters

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_parameters.json" goto :skip_write_parameters
echo.
echo %electionguard_exe% write-parameters --n %eg_n% --k %eg_k% --date "%eg_date%" --info "%eg_info%"
%electionguard_exe% write-parameters --n %eg_n% --k %eg_k% --date "%eg_date%" --info "%eg_info%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_write_parameters

rem ---- Write hashes

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\hashes.json" goto :skip_write_hashes
echo.
echo %electionguard_exe% --insecure-deterministic write-hashes
%electionguard_exe% --insecure-deterministic write-hashes
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_write_hashes

rem ---- Create the guardians directory

if exist "%guardians_dir%" goto :skip_create_guardians_dir
echo.
echo mkdir "%guardians_dir%"
mkdir "%guardians_dir%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_create_guardians_dir

rem ---- For each guardian

set /a "eg_n_minus_1=eg_n - 1"
for /L %%N in (0, 1, %eg_n_minus_1%) do call :sub_egtest_per_guardian %%N

rem ---- Write HashesExt

echo.
echo TODO: Write HashesExt

rem ---- Write election public key

echo.
echo TODO: Write election public key

rem ---- XXXX

rem echo.
rem echo XXXX

exit /b 0 & rem ------- end of :sub_egtest

rem ======================================================= Subroutine: ElectionGuard tests - per guardian actions
:sub_egtest_per_guardian

set /a "i=%1"

(set guardian_dir=%guardians_dir%\%i%)

if exist "%guardian_dir%" goto :skip_create_guardian_dir
echo.
echo mkdir "%guardian_dir%"
mkdir "%guardian_dir%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_create_guardian_dir

(set guardian_secret_key_file=%guardian_dir%\guardian_%i%.SECRET_key.json)
(set guardian_public_key_file=%guardian_dir%\guardian_%i%.public_key.json)
(set guardian_name=Guardian %i%)

echo.
echo ---- Guardian %i%
echo.
echo Secret key file: %guardian_secret_key_file%
echo Public key file: %guardian_public_key_file%

if not exist "%guardian_secret_key_file%" goto :dont_skip_generate_secret_key
if not exist "%guardian_public_key_file%" goto :dont_skip_generate_secret_key
echo Guardian %i% secret and public key files already exist.
goto :skip_generate_secret_key
:dont_skip_generate_secret_key
echo.
echo %electionguard_exe% --insecure-deterministic guardian-secret-key-generate --i %i% --name "%guardian_name%"
%electionguard_exe% --insecure-deterministic guardian-secret-key-generate --i %i% --name "%guardian_name%"
if "%ERRORLEVEL%" NEQ "0" exit /b
:skip_generate_secret_key

if not exist "%guardian_secret_key_file%" (
    echo.
    echo ERROR: Guardian %i% secret key file does not exist: %guardian_secret_key_file%
    exit /b 1
)
if not exist "%guardian_public_key_file%" (
    echo.
    echo ERROR: Guardian %i% public key file does not exist: %guardian_public_key_file%
    exit /b 1
)

exit /b 0 & rem ------- end of :sub_egtest_per_guardian
