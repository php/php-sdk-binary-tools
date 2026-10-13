@echo off

call %~dp0phpsdk-starter.bat -c vc15 -a arm64 %*

exit /b %ERRORLEVEL%
