@echo off

call %~dp0phpsdk-starter.bat -c vs17 -a arm64 %*

exit /b %ERRORLEVEL%

