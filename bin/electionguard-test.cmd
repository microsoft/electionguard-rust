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
set /a clarg_erase_artifacts=0
(set clarg_profile=debug)

:more_cmdline_args

if "_%1" EQU "_" (
    goto :no_more_cmdline_args
)
if "%1" EQU "--help" (
    set /a clarg_help=1
    goto :no_more_cmdline_args
)
if "%1" EQU "--erase-artifacts" (
    set /a clarg_erase_artifacts=1
    goto :next_cmdline_arg
)
if "%1" EQU "--debug" (
    (set clarg_profile=debug)
    goto :next_cmdline_arg
)
if "%1" EQU "--release" (
    (set clarg_profile=release)
    goto :next_cmdline_arg
)
echo ERROR: Unknown command line argument: %1
goto :error

:next_cmdline_arg
shift /1
goto :more_cmdline_args

:no_more_cmdline_args

rem ----- Handle the --help command

if "%clarg_help%" NEQ "0" (
    echo Usage:
    echo     electionguard-test.cmd --help
    echo     electionguard-test.cmd [--debug or --release] [--erase-artifacts]
    goto :success
)

rem ----- Figure the full path to directory containing this script.

(set this_script_dir=%~dp0)
(set this_script_dir=%this_script_dir:~0,-1%)
echo this_script_dir=%this_script_dir%

rem ----- Check the ELECTIONGUARD_ARTIFACTS_DIR

if "_%ELECTIONGUARD_ARTIFACTS_DIR%" EQU "_" (
    echo ERROR: ELECTIONGUARD_ARTIFACTS_DIR is not set.
    goto :error
)

echo ELECTIONGUARD_ARTIFACTS_DIR=%ELECTIONGUARD_ARTIFACTS_DIR%
if not exist "%ELECTIONGUARD_ARTIFACTS_DIR%" (
    echo ERROR: ELECTIONGUARD_ARTIFACTS_DIR does not exist: %ELECTIONGUARD_ARTIFACTS_DIR%
    goto :error
)

(set guardians_dir=%ELECTIONGUARD_ARTIFACTS_DIR%\guardians)
echo guardians_dir=%guardians_dir%

rem ----- Change to the directory from which we should run cargo.

for %%F in (%this_script_dir%\..\src\xxx) do (set electionguard_cargo_dir=%%~dpF)
(set electionguard_cargo_dir=%electionguard_cargo_dir:~0,-1%)
echo electionguard_cargo_dir=%electionguard_cargo_dir%
if not exist "%electionguard_cargo_dir%" (
    echo ERROR: electionguard_cargo_dir does not exist: %electionguard_cargo_dir%
    goto :error
)

echo.
echo cd /d "%electionguard_cargo_dir%"
cd /d "%electionguard_cargo_dir%"
if "%ERRORLEVEL%" NEQ "0" goto :error

rem ---- Run tests

echo clarg_profile=%clarg_profile%

(set cargo_profile_build_flag=)
if "%clarg_profile%" EQU "debug" (
    (set cargo_profile_build_flag=)
) else (if "%clarg_profile%" EQU "release" (
    (set cargo_profile_build_flag=--release)
) else (
    echo ERROR: Unknown cargo profile: %clarg_profile%
    goto :error
))

echo cargo_profile_build_flag=%cargo_profile_build_flag%

echo.
echo cargo test %cargo_profile_build_flag% -- --test-threads=1 --nocapture
cargo test %cargo_profile_build_flag% -- --test-threads=1 --nocapture
if "%ERRORLEVEL%" NEQ "0" goto :error

rem ---- Build electionguard.exe

(set electionguard_exe=%electionguard_cargo_dir%\target\%clarg_profile%\electionguard.exe)

echo.
echo cargo build %cargo_profile_build_flag% -p electionguard
cargo build %cargo_profile_build_flag% -p electionguard
if "%ERRORLEVEL%" NEQ "0" goto :error

if not exist "%electionguard_exe%" (
    echo ERROR: electionguard.exe does not exist: %electionguard_exe%
    goto :error
)

rem ---- erase ELECTIONGUARD_ARTIFACTS_DIR

if "%clarg_erase_artifacts%" EQU "0" goto :skip_erase_artifacts
if not exist "%ELECTIONGUARD_ARTIFACTS_DIR%" goto :skip_erase_artifacts
echo.
echo rmdir /s /q "%ELECTIONGUARD_ARTIFACTS_DIR%"
rmdir /s /q "%ELECTIONGUARD_ARTIFACTS_DIR%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_erase_artifacts

rem ---- ensure ELECTIONGUARD_ARTIFACTS_DIR exists

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%" goto :skip_create_artifacts_dir
echo.
echo mkdir "%ELECTIONGUARD_ARTIFACTS_DIR%"
mkdir "%ELECTIONGUARD_ARTIFACTS_DIR%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_create_artifacts_dir

rem ---- Write random seed

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\pseudorandom_seed_defeats_all_secrecy.bin" goto :skip_write_random_seed
echo.
echo %electionguard_exe% write-random-seed
%electionguard_exe% write-random-seed
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_write_random_seed

rem ---- Write election manifest (canonical)

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_manifest_canonical.bin" goto :skip_write_manifest_canonical
echo.
echo %electionguard_exe% write-manifest --in-example --out-format canonical
%electionguard_exe% write-manifest --in-example --out-format canonical
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_write_manifest_canonical

rem ---- Write election manifest (pretty)

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_manifest_pretty.json" goto :skip_write_manifest_pretty
echo.
echo %electionguard_exe% write-manifest --out-format pretty
%electionguard_exe% write-manifest --out-format pretty
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_write_manifest_pretty

rem ---- Write election parameters

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\election_parameters.json" goto :skip_write_parameters
echo.
echo %electionguard_exe% write-parameters --n %eg_n% --k %eg_k% --date "%eg_date%" --info "%eg_info%"
%electionguard_exe% write-parameters --n %eg_n% --k %eg_k% --date "%eg_date%" --info "%eg_info%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_write_parameters

rem ---- Write hashes

if exist "%ELECTIONGUARD_ARTIFACTS_DIR%\hashes.json" goto :skip_write_hashes
echo.
echo %electionguard_exe% --insecure-deterministic write-hashes
%electionguard_exe% --insecure-deterministic write-hashes
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_write_hashes

rem ---- Create the guardians directory

if exist "%guardians_dir%" goto :skip_create_guardians_dir
echo.
echo mkdir "%guardians_dir%"
mkdir "%guardians_dir%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_create_guardians_dir

rem ---- For each guardian

set /a "eg_n_minus_1=eg_n - 1"
for /L %%N in (0, 1, %eg_n_minus_1%) do call :sub_create_guardian %%N

rem ---- Write HashesExt

echo.
echo TODO: Write HashesExt

rem ---- Write election public key

echo.
echo TODO: Write election public key

rem ---- XXXX

rem echo.
rem echo XXXX

rem ---- Success!
goto :success

:sub_create_guardian & rem ----------------------- For each guardian

set /a "i=%1"

(set guardian_dir=%guardians_dir%\%i%)
(set guardian_public_key_file=%guardian_dir%\guardian_%i%.public_key.json)
(set guardian_private_key_file=%guardian_dir%\guardian_%i%.private_key.KEEP_THIS_SECRET.json)
(set guardian_name=Guardian %i%)

if exist "%guardian_dir%" goto :skip_create_guardian_dir
echo.
echo mkdir "%guardian_dir%"
mkdir "%guardian_dir%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_create_guardian_dir

if not exist "%guardian_private_key_file%" goto :dont_skip_generate_private_key
if not exist "%guardian_public_key_file%" goto :dont_skip_generate_private_key
echo Guardian %i% public and private key files already exist.
goto :skip_generate_private_key
:dont_skip_generate_private_key
echo.
rem echo %electionguard_exe% --insecure-deterministic guardian-key-generate --i %i% --public-key-out-file "%guardian_public_key_file%" --private-key-out-file "%guardian_private_key_file%"
echo %electionguard_exe% --insecure-deterministic guardian-key-generate --i %i% --name "%guardian_name%"
%electionguard_exe% --insecure-deterministic guardian-key-generate --i %i% --name "%guardian_name%"
if "%ERRORLEVEL%" NEQ "0" goto :error
:skip_generate_private_key

if not exist "%guardian_private_key_file%" goto :error
if not exist "%guardian_public_key_file%" goto :error

echo Guardian %i% public key file: %guardian_public_key_file%
echo Guardian %i% private key file: %guardian_private_key_file%

exit /b

rem ----------------------- exit conditions

:error
endlocal
exit /b 1

:success
endlocal
exit /b 0
