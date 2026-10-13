@echo off

call %~dp0phpsdk-starter.bat -c vs16 -a arm64 %*

exit /b %ERRORLEVEL%
