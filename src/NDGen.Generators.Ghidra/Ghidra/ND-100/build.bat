@echo off
set GHIDRA_INSTALL_DIR=C:\Utils\Ghidra\ghidra_12.0.4_PUBLIC
echo Building ND-100 extension against %GHIDRA_INSTALL_DIR%
call "%~dp0gradlew.bat" buildExtension %*
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo Build successful.
for %%f in ("%~dp0dist\*.zip") do echo Extension zip: %%f
echo.
echo To install: Ghidra ^> File ^> Install Extensions ^> Add ^> select the zip above ^> restart Ghidra
