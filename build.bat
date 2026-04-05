@echo off
setlocal EnableExtensions
REM Full plugin build: C# codegen into .\ND-100\ then Gradle buildExtension.
REM
REM GHIDRA_INSTALL_DIR must be set to your Ghidra installation root before running, e.g.:
REM   set GHIDRA_INSTALL_DIR=C:\Utils\Ghidra\ghidra_12.0.4_PUBLIC
set "REPO=%~dp0"
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"

if not defined GHIDRA_INSTALL_DIR (
  echo ERROR: GHIDRA_INSTALL_DIR is not set.
  echo   set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_^<version^>_PUBLIC
  exit /b 1
)
if not exist "%GHIDRA_INSTALL_DIR%" (
  echo ERROR: GHIDRA_INSTALL_DIR does not exist: %GHIDRA_INSTALL_DIR%
  exit /b 1
)

set "SRC=%REPO%\src\NDGen.Generators.Ghidra\Ghidra\ND-100"
set "OUT=%REPO%\ND-100"

cd /d "%REPO%"

if /I "%~1"=="gradle-only" goto GRADLE

echo === [1/2] Generate SLEIGH, Java glue, manual into ND-100\ ===
where dotnet >nul 2>nul || (echo ERROR: dotnet not in PATH & exit /b 1)

if not exist "%REPO%\nd100-definitions\specs\cpu.yaml" (
  echo Initializing nd100-definitions submodule...
  git -C "%REPO%" submodule update --init --recursive
  if errorlevel 1 exit /b 1
)

dotnet build "%REPO%\ND100.Ghidra.sln" -c Release
if errorlevel 1 exit /b 1
dotnet run --project "%REPO%\src\ND100.Ghidra.Tool\ND100.Ghidra.Tool.csproj" -c Release --no-build
if errorlevel 1 exit /b 1

:GRADLE
echo === [2/2] Copy Gradle wrapper + Java sources, then buildExtension ===
if not exist "%SRC%\build.gradle" (
  echo ERROR: Missing Gradle project at "%SRC%"
  exit /b 1
)

mkdir "%OUT%" 2>nul
copy /Y "%SRC%\build.gradle" "%OUT%\"
copy /Y "%SRC%\settings.gradle" "%OUT%\"
copy /Y "%SRC%\gradlew.bat" "%OUT%\"
xcopy /Y /S /I "%SRC%\gradle" "%OUT%\gradle\"
xcopy /Y /S /I "%SRC%\src" "%OUT%\src\"
copy /Y "%SRC%\extension.properties" "%OUT%\"
copy /Y "%SRC%\Module.manifest" "%OUT%\"

REM Inject module version into extension.properties (@extversion@ is replaced by Gradle with the Ghidra version)
if not defined MODULE_VERSION set "MODULE_VERSION=0.1.0"
powershell -Command "(Get-Content '%OUT%\extension.properties') -replace '@moduleversion@', '%MODULE_VERSION%' | Set-Content '%OUT%\extension.properties'"

pushd "%OUT%"
call gradlew.bat --no-daemon clean buildExtension
set "ERR=%ERRORLEVEL%"
popd
if not "%ERR%"=="0" (
  echo ERROR: Gradle buildExtension failed
  exit /b 1
)

echo.
echo === Done. Extension ZIP under: %OUT%\dist\ ===
dir /b "%OUT%\dist\ghidra_*_ND-100.zip" 2>nul
exit /b 0
