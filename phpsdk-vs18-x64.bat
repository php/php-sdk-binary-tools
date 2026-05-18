@echo off

call %~dp0phpsdk-starter.bat -c vs18 -a x64 %*

exit /b %ERRORLEVEL%
