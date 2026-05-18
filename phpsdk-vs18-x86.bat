@echo off

call %~dp0phpsdk-starter.bat -c vs18 -a x86 %*

exit /b %ERRORLEVEL%
