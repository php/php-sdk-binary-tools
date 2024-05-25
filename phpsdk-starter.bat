@echo off

setlocal enableextensions enabledelayedexpansion

rem make sure we end up where we started (for VS2017)
set "VSCMD_START_DIR=%CD%"
set "__VSCMD_ARG_NO_LOGO=yes"

rem this will be eventually overridden by phpsdk_setvars, but nothing wrong to use the same name here
set PHP_SDK_ROOT_PATH=%~dp0
set PHP_SDK_ROOT_PATH=%PHP_SDK_ROOT_PATH:~0,-1%

:getopt
if /i "%1" equ "-h" goto help
if /i "%1" equ "-c" set CRT=%2 & shift
if /i "%1" equ "-a" set ARCH=%2 & shift
if /i "%1" equ "-s" set TOOLSET=%2 & shift
if /i "%1" equ "-t" set TASK=%2 & shift
if /i "%1" equ "--task-args" set TASK_ARGS=%2 & shift
shift
if not (%1)==() goto getopt

if "%CRT%" equ "" goto help
if "%ARCH%" equ "" goto help
goto skip_help

:help
	echo Usage: phpsdk-starter -c ^<crt^> -a ^<arch^> [-t ^<task_script.bat^> [task script args]]
	exit /b 0

:skip_help

set CRT=%CRT: =%
set ARCH=%ARCH: =%

set PHP_SDK_RUN_FROM_ROOT=1


title PHP SDK %CRT% %ARCH%

call %PHP_SDK_ROOT_PATH%\bin\phpsdk_setshell.bat %CRT% %ARCH% %TOOLSET%

set PHP_SDK_RUN_FROM_ROOT=
set CRT=
set ARCH=

if errorlevel 3 (
	exit /b !ERRORLEVEL!
)

if "%TASK%" neq "" (
	if exist "%TASK%" (
		set TASK_ARGS=%TASK_ARGS:"=%

		if exist "%PHP_SDK_ROOT_PATH%\phpsdk-local.bat" (
			cmd /c "!PHP_SDK_VS_SHELL_CMD! && %PHP_SDK_ROOT_PATH%\bin\phpsdk_setvars.bat && %PHP_SDK_ROOT_PATH%\phpsdk-local.bat && %TASK% !TASK_ARGS!"
		) else (
			cmd /c "!PHP_SDK_VS_SHELL_CMD! && %PHP_SDK_ROOT_PATH%\bin\phpsdk_setvars.bat && %TASK% !TASK_ARGS!"
		)
		set TASK=
		exit /b !ERRORLEVEL!
	) else (
		echo could not find the task file
		set TASK=
		exit /b 3
	)
)

if exist "%PHP_SDK_ROOT_PATH%\phpsdk-local.bat" (
	cmd /k "!PHP_SDK_VS_SHELL_CMD! && set __VSCMD_ARG_NO_LOGO=&& set VSCMD_START_DIR=&& %PHP_SDK_ROOT_PATH%\bin\phpsdk_setvars.bat && %PHP_SDK_ROOT_PATH%\bin\phpsdk_dumpenv.bat && %PHP_SDK_ROOT_PATH%\phpsdk-local.bat && echo. && set prompt=$P$_$+$$$S"
) else (
	cmd /k "!PHP_SDK_VS_SHELL_CMD! && set __VSCMD_ARG_NO_LOGO=&& set VSCMD_START_DIR=&& %PHP_SDK_ROOT_PATH%\bin\phpsdk_setvars.bat && %PHP_SDK_ROOT_PATH%\bin\phpsdk_dumpenv.bat && set prompt=$P$_$+$$$S"
)

exit /b !ERRORLEVEL!

