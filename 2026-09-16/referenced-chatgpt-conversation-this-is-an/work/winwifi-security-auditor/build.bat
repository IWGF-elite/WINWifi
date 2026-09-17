@echo off
set "PATH=C:\Program Files\dotnet;%PATH%"
set "NUGET_PACKAGES=%USERPROFILE%\.nuget\packages"
set "NUGET_FALLBACK_PACKAGES="
cd /d "%~dp0"
dotnet build WinWiFi.sln -c Release --nologo -v q %*
