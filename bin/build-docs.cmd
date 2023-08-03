@echo off
setlocal enableextensions enabledelayedexpansion
(set errorlevel=)

rem ----- Figure the full path to directory containing this script.

echo.

(set this_script_dir=%~dp0)
(set this_script_dir=%this_script_dir:~0,-1%)
echo this_script_dir=%this_script_dir%

rem ----- Change to the electionguard_src_dir from which we should run cargo.

for %%F in (%this_script_dir%\..\src\xxx) do (set electionguard_src_dir=%%~dpF)
(set electionguard_src_dir=%electionguard_src_dir:~0,-1%)
echo electionguard_src_dir=%electionguard_src_dir%

prompt [$P]$_

echo on
cd /d "%electionguard_src_dir%"
@echo off
if "%ERRORLEVEL%" NEQ "0" exit /b
echo.

rem ----- cargo doc

(set source_doc_reldir=..\doc)
echo source_doc_reldir=%source_doc_reldir%

@REM This is where cargo doc will put the generated documentation.
if "%CARGO_TARGET_DIR%" == "" (
    (set cargo_target_doc_reldir=target\doc)
) else (
    (set cargo_target_doc_reldir=%CARGO_TARGET_DIR%\doc)
)
echo cargo_target_doc_reldir=%cargo_target_doc_reldir%

(set target_docs_reldir=%cargo_target_doc_reldir%s)
echo target_docs_reldir=%target_docs_reldir%

(set target_docs_crates_reldir=%target_docs_reldir%\crates)
echo target_docs_crates_reldir=%target_docs_crates_reldir%

(set cargo_profile_build_flag=--release)

(set frozen_offline=--frozen --offline)

rem (set verbose=--verbose)
(set verbose=)

rem NOTE: Don't specify %cargo_profile_build_flag% or --release to `cargo clean`.
rem That will cause it clean the target/release build directory in addition to the target/doc directory.

echo on
@REM cargo clean %frozen_offline% --doc
@REM @if "%ERRORLEVEL%" NEQ "0" exit /b

@if exist "%cargo_target_doc_reldir%" (
    rmdir /s /q "%cargo_target_doc_reldir%"
    @if "%ERRORLEVEL%" NEQ "0" exit /b
)

@if exist "%target_docs_reldir%" (
    rmdir /s /q "%target_docs_reldir%"
    @if "%ERRORLEVEL%" NEQ "0" exit /b
)

mkdir "%target_docs_reldir%"
@if "%ERRORLEVEL%" NEQ "0" exit /b

@REM Build the lib crates documentation using `cargo doc`.
cargo doc %verbose% %cargo_profile_build_flag% %frozen_offline% --no-deps --lib -p eg -p util
@if "%ERRORLEVEL%" NEQ "0" exit /b

@REM The cmd built-in "move" sometimes fails with "Access is denied."
@REM Robocopy is much more reliable.
robocopy "%cargo_target_doc_reldir%" "%target_docs_reldir%\crates" * /e /move /ns /nc /nfl /ndl /np /njh /njs
@if "%ERRORLEVEL%" NEQ "1" (
    @echo errorlevel is !ERRORLEVEL!. A value other than 1 here indicates robocopy error.
    @exit /b 1
)

@call :sub_invoke_rustdoc "index.md"
@if "%ERRORLEVEL%" NEQ "0" exit /b

@call :sub_invoke_rustdoc "implementation_guide\implementation_guide.md" "implementation_guide"
@if "%ERRORLEVEL%" NEQ "0" exit /b

@call :sub_invoke_rustdoc "apps\electionguard.md" "apps"
@if "%ERRORLEVEL%" NEQ "0" exit /b

@call :sub_invoke_rustdoc "specs\ElectionGuard_2.0_Serialization_Specification.md" "specs"
@if "%ERRORLEVEL%" NEQ "0" exit /b

robocopy "%source_doc_reldir%\specs" "%target_docs_reldir%\specs" *.pdf /ns /nc /nfl /ndl /np /njh /njs
@if "%ERRORLEVEL%" NEQ "1" (
    @echo errorlevel is !ERRORLEVEL!. A value other than 1 here indicates robocopy error.
    @exit /b 1
)

robocopy .. "%target_docs_reldir%" LICENSE /ns /nc /nfl /ndl /np /njh /njs
@if "%ERRORLEVEL%" NEQ "1" (
    @echo errorlevel is !ERRORLEVEL!. A value other than 1 here indicates robocopy error.
    @exit /b 1
)

@echo off

rem ----- Success!

echo Docs built succesfully^^!

echo.
(set output_dir=%electionguard_src_dir%\%target_docs_reldir%)
echo Output dir: %output_dir%

(set index_html_url=%output_dir:\=/%/index.html)
(set index_html_url=!index_html_url: =%%20!)
(set index_html_url=file:///%index_html_url%)
echo Table of Contents: %index_html_url%

exit /b 0

rem ======================================================= Subroutine: invoke rustdoc
:sub_invoke_rustdoc
@setlocal
@REM @echo ====vvvv==== :sub_invoke_rustdoc ====vvvv====
@REM @echo %%1=%1
@REM @echo %%2=%2

@(set source_relfile=%~1)
@(set target_reldir=%~2)

@(set out_dir_flag=--out-dir "%target_docs_reldir%")
@if "%target_reldir%" == "" goto :blank_target_reldir
@(set out_dir_flag=--out-dir "%target_docs_reldir%\%target_reldir%")
:blank_target_reldir

rustdoc %out_dir_flag% "%source_doc_reldir%\%source_relfile%"
@if "%ERRORLEVEL%" NEQ "0" (endlocal & exit /b)

@REM --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat

@REM @echo ====^^^^^^^^==== :sub_invoke_rustdoc ====^^^^^^^^====
@endlocal
@exit /b 0 & rem ------- end of :sub_invoke_rustdoc
