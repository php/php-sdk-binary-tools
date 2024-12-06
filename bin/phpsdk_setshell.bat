@echo off

if not defined PHP_SDK_RUN_FROM_ROOT (
	echo This script should not be run directly.
	echo Use starter scripts looking like phpsdk-^<crt^>-^<arch^>.bat in the PHP SDK root instead.
	goto out_error
)


if "%1"=="" goto :help
if "%1"=="/?" goto :help
if "%1"=="-h" goto :help
if "%1"=="--help" goto :help
if "%2"=="" goto :help

cmd /c "exit /b 0"

set PHP_SDK_VS=%1
if /i not "%PHP_SDK_VS:~0,2%"=="vc" (
	if /i not "%PHP_SDK_VS:~0,2%"=="vs" (
:malformed_vc_string
		echo Malformed CRT string "%1"
		set PHP_SDK_VS=
		goto out_error
	)
)
if ""=="%PHP_SDK_VS:~2%" (
	goto malformed_vc_string
)
set /a TMP_CHK=%PHP_SDK_VS:~2%
if 14 gtr %TMP_CHK% (
	if "0"=="%TMP_CHK%" (
		if not "0"=="%PHP_SDK_VS:~2%" (
			set TMP_CHK=
			goto malformed_vc_string
		)
	)

	echo At least vc14 is required
	set PHP_SDK_VS=
	set TMP_CHK=
	goto out_error
)
set PHP_SDK_VS_NUM=%TMP_CHK%
set TMP_CHK=

rem check target arch
if "%2"=="x86" set PHP_SDK_ARCH=%2
if "%2"=="x64" set PHP_SDK_ARCH=%2
if "%2"=="x86_64" set PHP_SDK_ARCH=x64
if "%2"=="amd64" set PHP_SDK_ARCH=x64
if "%2"=="arm64" set PHP_SDK_ARCH=%2
if "%PHP_SDK_ARCH%"=="" (
	echo Unsupported target arch %2 >&2
	goto out_error
)

set TOOLSET=
if NOT "%3"=="" SET TOOLSET=%3 

rem check OS arch
rem todo: allow user choose host sdk arch (i.e. x64 target can be compiled at x64(native) or x86(cross))
for /f "usebackq tokens=1*" %%i in (`wmic cpu get Architecture /value /format:table ^| findstr /r "[1234567890][1234567890]*"`) do (
	set PHP_SDK_OS_ARCH_NUM=%%i
)

goto os_arch_cases
:os_arch_error
echo Unsupported OS arch %PHP_SDK_OS_ARCH% >&2
goto out_error

:os_arch_cases
if "%PHP_SDK_OS_ARCH_NUM%"=="0" set PHP_SDK_OS_ARCH=x86
if "%PHP_SDK_OS_ARCH_NUM%"=="1" (set PHP_SDK_OS_ARCH=mips && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="2" (set PHP_SDK_OS_ARCH=alpha && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="3" (set PHP_SDK_OS_ARCH=ppc && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="4" (set PHP_SDK_OS_ARCH=shx && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="5" (set PHP_SDK_OS_ARCH=arm32 && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="6" (set PHP_SDK_OS_ARCH=ia64 && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="7" (set PHP_SDK_OS_ARCH=alpha64 && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="8" (set PHP_SDK_OS_ARCH=msil && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="9" set PHP_SDK_OS_ARCH=x64
rem wow64
if "%PHP_SDK_OS_ARCH_NUM%"=="10" set PHP_SDK_OS_ARCH=x86
if "%PHP_SDK_OS_ARCH_NUM%"=="11" (set PHP_SDK_OS_ARCH=neutral && goto os_arch_error)
if "%PHP_SDK_OS_ARCH_NUM%"=="12" set PHP_SDK_OS_ARCH=arm64
if "%PHP_SDK_OS_ARCH_NUM%"=="13" (set PHP_SDK_OS_ARCH=arm32 && goto os_arch_error)
rem woa64
if "%PHP_SDK_OS_ARCH_NUM%"=="14" set PHP_SDK_OS_ARCH=x86
if "%PHP_SDK_OS_ARCH%"=="" (
	goto os_arch_error
)

set PHP_SDK_OS_ARCH_NUM=

rem cross compile is ok, so we donot need this
rem if not /i "%PHP_SDK_ARCH%"=="PHP_SDK_OS_ARCH" (
rem 	echo 32-bit OS detected, native 64-bit toolchain is unavailable.
rem 	goto out_error
rem )

rem get vc base dir
if 15 gtr %PHP_SDK_VS_NUM% (
	rem for arch other than x86, use WOW6432
	if /i not "%PHP_SDK_OS_ARCH%"=="x86" (
		set TMPKEY=HKLM\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\%PHP_SDK_VS:~2%.0\Setup\VC
	) else (
		set TMPKEY=HKLM\SOFTWARE\Microsoft\VisualStudio\%PHP_SDK_VS:~2%.0\Setup\VC
	)
	reg query !TMPKEY! /v ProductDir >nul 2>&1
	if errorlevel 1 (
		echo Couldn't determine VC%PHP_SDK_VS:~2% directory
		goto out_error;
	)
	for /f "tokens=2*" %%a in ('reg query !TMPKEY! /v ProductDir') do set PHP_SDK_VC_DIR=%%b
) else (
	rem build the version range, e.g. "[15,16)"
	set /a PHP_SDK_VS_RANGE=PHP_SDK_VS_NUM + 1
	set PHP_SDK_VS_RANGE="[%PHP_SDK_VS_NUM%,!PHP_SDK_VS_RANGE%!)"

	set APPEND=x86.x64
	if /i "%PHP_SDK_OS_ARCH%"=="arm64" (
		set APPEND=ARM64
	)
	set VS_VERSION_ARGS="-latest"
	if "%TOOLSET%"=="" set VS_VERSION_ARGS=-version !PHP_SDK_VS_RANGE!
	for /f "tokens=1* delims=: " %%a in ('%~dp0\vswhere -nologo !VS_VERSION_ARGS! -requires Microsoft.VisualStudio.Component.VC.Tools.!APPEND! -property installationPath -format text') do (
		set PHP_SDK_VC_DIR=%%b\VC
	)
	if not exist "!PHP_SDK_VC_DIR!" (
		for /f "tokens=1* delims=: " %%a in ('%~dp0\vswhere -nologo !VS_VERSION_ARGS! -products Microsoft.VisualStudio.Product.BuildTools -requires Microsoft.VisualStudio.Component.VC.Tools.!APPEND! -property installationPath -format text') do (
			set PHP_SDK_VC_DIR=%%b\VC
		)
		if not exist "!PHP_SDK_VC_DIR!" (
			rem check for a preview release
			for /f "tokens=1* delims=: " %%a in ('%~dp0\vswhere -nologo !VS_VERSION_ARGS! -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.!APPEND! -property installationPath -format text') do (
				set PHP_SDK_VC_DIR=%%b\VC
			)
			if not exist "!PHP_SDK_VC_DIR!" (
				echo Could not determine '%PHP_SDK_VS%' directory
				set /p PHP_SDK_VC_DIR=Input '%PHP_SDK_VS%' directory:
			)
			if not exist "!PHP_SDK_VC_DIR!" (
				echo Could not determine '%PHP_SDK_VS%' directory
				goto out_error;
			)
		)
	)
	set VSCMD_ARG_no_logo=nologo
)
set APPEND=
set TMPKEY=
set PHP_SDK_VS_RANGE=

if 15 gtr %PHP_SDK_VS_NUM% (
	rem get sdk dir
	rem if 10.0 is available, it's ok
	rem for arch other than x86, use WOW6432
	if /i not "%PHP_SDK_OS_ARCH%"=="x86" (
		set TMPKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v10.0
	) else (
		set TMPKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0
	)
	for /f "tokens=2*" %%a in ('reg query "!TMPKEY!" /v InstallationFolder') do (
		for /f "tokens=2*" %%c in ('reg query "!TMPKEY!" /v ProductVersion') do (
			if exist "%%bInclude\%%d.0\um\Windows.h" (
				goto got_sdk
			)
		)
	)

	rem Otherwise 8.1 should be available anyway
	rem for arch other than x86, use WOW6432
	if /i not "%PHP_SDK_OS_ARCH%"=="x86" (
		set TMPKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Microsoft SDKs\Windows\v8.1
	) else (
		set TMPKEY=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1
	)
	for /f "tokens=2*" %%a in ('reg query "!TMPKEY!" /v InstallationFolder') do (
		if exist "%%b\Include\um\Windows.h" (
			goto got_sdk
		)
	)

	echo Windows SDK not found.
	goto out_error;
:got_sdk
	set TMPKEY=
)

if /i "%PHP_SDK_ARCH%"=="x64" (
	set TARGET_ARCH_NAME=amd64
) else (
	set TARGET_ARCH_NAME=%PHP_SDK_ARCH%
)

if /i "%PHP_SDK_OS_ARCH%"=="x64" (
	set HOST_ARCH_NAME=amd64
) else (
	set HOST_ARCH_NAME=%PHP_SDK_ARCH%
)

if "%HOST_ARCH_NAME%"=="%TARGET_ARCH_NAME%" (
	set VCVARSALL_ARCH_NAME=%HOST_ARCH_NAME%
) else if "%HOST_ARCH_NAME%_%TARGET_ARCH_NAME%"=="amd64_x86" (
	set VCVARSALL_ARCH_NAME=%TARGET_ARCH_NAME%
) else (
	set VCVARSALL_ARCH_NAME=%HOST_ARCH_NAME%_%TARGET_ARCH_NAME%
)
if 15 gtr %PHP_SDK_VS_NUM% (
    if NOT "%TOOLSET%"=="" (
        set PHP_SDK_VS_SHELL_CMD="!PHP_SDK_VC_DIR!\vcvarsall.bat" !VCVARSALL_ARCH_NAME! -vcvars_ver=%TOOLSET%
    ) else (
        set PHP_SDK_VS_SHELL_CMD="!PHP_SDK_VC_DIR!\vcvarsall.bat" !VCVARSALL_ARCH_NAME!
    )
) else (
    if NOT "%TOOLSET%"=="" (
        set PHP_SDK_VS_SHELL_CMD="!PHP_SDK_VC_DIR!\Auxiliary\Build\vcvarsall.bat" !VCVARSALL_ARCH_NAME! -vcvars_ver=%TOOLSET%
    ) else (
        set PHP_SDK_VS_SHELL_CMD="!PHP_SDK_VC_DIR!\Auxiliary\Build\vcvarsall.bat" !VCVARSALL_ARCH_NAME!
    )
)
set VCVARSALL_ARCH_NAME=

rem echo Visual Studio VC path %PHP_SDK_VC_DIR%
rem echo Windows SDK path %PHP_SDK_WIN_SDK_DIR%


goto out

:help
	echo "Start Visual Studio command line for PHP SDK"
	echo "Usage: %0 vc arch" 
	echo nul

:out_error
	exit /b 3

:out
rem	echo Shell configuration complete
	exit /b 0

goto :eof

