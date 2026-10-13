@echo off

call %~dp0phpsdk-starter.bat -c vs18 -a arm64 %*

exit /b %ERRORLEVEL%
