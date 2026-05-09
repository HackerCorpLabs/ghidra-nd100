# Cross-platform build for the Ghidra ND-100 processor module.
#
# Works on:
#   - Linux & macOS:  GNU Make + POSIX shell.
#   - Windows:        GNU Make from native cmd (e.g. chocolatey, MSYS2 mingw32-make,
#                     or `make` from Build Tools), and also from Git Bash / WSL.
#
# Required tools: dotnet (8+), java (21), git.
# GHIDRA_INSTALL_DIR must point at the Ghidra installation root for the gradle target.

REPO       := $(CURDIR)
SRC_TPL    := $(REPO)/src/NDGen.Generators.Ghidra/Ghidra/ND-100
OUT        := $(REPO)/ND-100
SLN        := $(REPO)/ND100.Ghidra.sln
TOOL_PROJ  := $(REPO)/src/ND100.Ghidra.Tool/ND100.Ghidra.Tool.csproj
MODULE_VERSION ?= 0.1.0

# Allow .NET 9-targeted projects to run on a newer SDK (e.g. .NET 10) when 9.x isn't installed.
export DOTNET_ROLL_FORWARD ?= Major

# ---------------------------------------------------------------------------
# OS detection. We dispatch per-recipe via $(IS_WIN) so each command runs
# natively on either cmd.exe or POSIX sh.
# ---------------------------------------------------------------------------
ifeq ($(OS),Windows_NT)
  IS_WIN  := 1
  GRADLEW := gradlew.bat
else
  IS_WIN  :=
  GRADLEW := ./gradlew
endif

# ---------------------------------------------------------------------------
# Auto-discover GHIDRA_INSTALL_DIR if the env var isn't set. We try a handful
# of common install paths and pick the first one that contains Ghidra.
# A path is considered valid only if Ghidra/application.properties exists.
# Override at any time with:  make ... GHIDRA_INSTALL_DIR=/path/to/ghidra
# ---------------------------------------------------------------------------
ifeq ($(strip $(GHIDRA_INSTALL_DIR)),)
ifdef IS_WIN
  GHIDRA_CANDIDATES := \
    $(wildcard C:/ghidra) \
    $(wildcard C:/Ghidra) \
    $(wildcard C:/ghidra_*_PUBLIC) \
    $(wildcard C:/Utils/Ghidra/ghidra_*_PUBLIC) \
    $(wildcard C:/Program*Files/ghidra*) \
    $(wildcard $(USERPROFILE)/ghidra) \
    $(wildcard $(USERPROFILE)/ghidra_*_PUBLIC)
else
  GHIDRA_CANDIDATES := \
    $(wildcard $(HOME)/ghidra) \
    $(wildcard $(HOME)/Ghidra) \
    $(wildcard $(HOME)/ghidra_*_PUBLIC) \
    $(wildcard $(HOME)/Ghidra/ghidra_*_PUBLIC) \
    $(wildcard /opt/ghidra) \
    $(wildcard /opt/ghidra_*_PUBLIC) \
    $(wildcard /usr/local/ghidra) \
    $(wildcard /usr/local/ghidra_*_PUBLIC) \
    $(wildcard /Applications/ghidra) \
    $(wildcard /Applications/ghidra_*_PUBLIC)
endif
  GHIDRA_FOUND := $(foreach d,$(GHIDRA_CANDIDATES),$(if $(wildcard $(d)/Ghidra/application.properties),$(d),))
  ifneq ($(strip $(GHIDRA_FOUND)),)
    # `override` lets us replace command-line "GHIDRA_INSTALL_DIR=" (empty)
    # in addition to the unset case.
    override GHIDRA_INSTALL_DIR := $(firstword $(GHIDRA_FOUND))
    export GHIDRA_INSTALL_DIR
    $(info ==> Auto-detected GHIDRA_INSTALL_DIR=$(GHIDRA_INSTALL_DIR))
  endif
endif

.DEFAULT_GOAL := help

.PHONY: help all build codegen scaffold inject-version gradle gradle-only \
        submodule refresh clean distclean check-dotnet check-ghidra

# ---------------------------------------------------------------------------
# Help (default target)
# ---------------------------------------------------------------------------
## help: Show this help (default target)
help:
ifdef IS_WIN
	@echo Ghidra ND-100 build - Makefile targets
	@echo.
	@echo   make help        Show this help
	@echo   make all         Full build: submodule + codegen + scaffold + gradle
	@echo   make codegen     Run the C# generator (dotnet build + run)
	@echo   make scaffold    Copy Gradle scaffold + generated files into ND-100\
	@echo   make gradle      Run Gradle buildExtension (skips codegen)
	@echo   make gradle-only Alias for 'make scaffold gradle'
	@echo   make submodule   Initialize nd100-definitions submodule if missing
	@echo   make refresh     Pull latest nd100-definitions submodule revision
	@echo   make clean       Remove ND-100\dist, ND-100\build, ND-100\.gradle
	@echo   make distclean   clean + remove generated files under ND-100\
	@echo.
	@echo Required env:  GHIDRA_INSTALL_DIR=C:\path\to\ghidra_VERSION_PUBLIC
	@echo Optional env:  MODULE_VERSION (default $(MODULE_VERSION))
	@echo                DOTNET_ROLL_FORWARD (default $(DOTNET_ROLL_FORWARD))
else
	@echo "Ghidra ND-100 build - Makefile targets"
	@echo ""
	@echo "  make help        Show this help"
	@echo "  make all         Full build: submodule + codegen + scaffold + gradle"
	@echo "  make codegen     Run the C# generator (dotnet build + run)"
	@echo "  make scaffold    Copy Gradle scaffold + generated files into ND-100/"
	@echo "  make gradle      Run Gradle buildExtension (skips codegen)"
	@echo "  make gradle-only Alias for 'make scaffold gradle'"
	@echo "  make submodule   Initialize nd100-definitions submodule if missing"
	@echo "  make refresh     Pull latest nd100-definitions submodule revision"
	@echo "  make clean       Remove ND-100/{dist,build,.gradle}"
	@echo "  make distclean   clean + remove generated files under ND-100/"
	@echo ""
	@echo "Required env:  GHIDRA_INSTALL_DIR=/path/to/ghidra_<version>_PUBLIC"
	@echo "Optional env:  MODULE_VERSION (default: $(MODULE_VERSION))"
	@echo "               DOTNET_ROLL_FORWARD (default: $(DOTNET_ROLL_FORWARD))"
endif

## all: Full pipeline
all: build

# `check-ghidra` runs first so we fail fast before expensive codegen if the
# Ghidra path is missing.
build: check-ghidra submodule codegen scaffold gradle

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
check-dotnet:
ifdef IS_WIN
	@where dotnet >nul 2>nul || (echo ERROR: dotnet is not in PATH. Install the .NET 8+ SDK. & exit 1)
else
	@command -v dotnet >/dev/null 2>&1 || { echo "ERROR: dotnet is not in PATH. Install the .NET 8+ SDK."; exit 1; }
endif

check-ghidra:
ifdef IS_WIN
	@if "$(GHIDRA_INSTALL_DIR)"=="" (echo ERROR: GHIDRA_INSTALL_DIR is not set. Example: set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_VERSION_PUBLIC & exit 1)
	@if not exist "$(GHIDRA_INSTALL_DIR)" (echo ERROR: GHIDRA_INSTALL_DIR does not exist: $(GHIDRA_INSTALL_DIR) & exit 1)
else
	@if [ -z "$$GHIDRA_INSTALL_DIR" ]; then \
	  echo "ERROR: GHIDRA_INSTALL_DIR is not set."; \
	  echo "  e.g. export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.4_PUBLIC"; \
	  exit 1; \
	fi; \
	if [ ! -d "$$GHIDRA_INSTALL_DIR" ]; then \
	  echo "ERROR: GHIDRA_INSTALL_DIR does not exist: $$GHIDRA_INSTALL_DIR"; exit 1; \
	fi
endif

# ---------------------------------------------------------------------------
# Submodule management
# ---------------------------------------------------------------------------
## submodule: init nd100-definitions submodule if missing
submodule:
ifdef IS_WIN
	@if not exist "$(REPO)/nd100-definitions/specs/cpu.yaml" (echo === Initializing nd100-definitions submodule & git -C "$(REPO)" submodule update --init --recursive) else (echo === Submodule already initialized)
else
	@if [ ! -f "$(REPO)/nd100-definitions/specs/cpu.yaml" ]; then \
	  echo "=== Initializing nd100-definitions submodule"; \
	  git -C "$(REPO)" submodule update --init --recursive; \
	else \
	  echo "=== Submodule already initialized"; \
	fi
endif

## refresh: pull latest revision of nd100-definitions
refresh:
ifdef IS_WIN
	@echo === Refreshing submodules to latest remote revision
else
	@echo "=== Refreshing submodules to latest remote revision"
endif
	git -C "$(REPO)" submodule sync --recursive
	git -C "$(REPO)" submodule update --init --remote --recursive

# ---------------------------------------------------------------------------
# C# code generation
# ---------------------------------------------------------------------------
## codegen: run the C# generator
codegen: check-dotnet submodule
ifdef IS_WIN
	@echo === [1/3] C# codegen (SLEIGH, Java glue, manual)
else
	@echo "=== [1/3] C# codegen (SLEIGH, Java glue, manual)"
endif
	dotnet build "$(SLN)" -c Release
	dotnet run --project "$(TOOL_PROJ)" -c Release --no-build

# ---------------------------------------------------------------------------
# Scaffold: copy template + generated files into ND-100/
# ---------------------------------------------------------------------------
## scaffold: copy Gradle scaffold into ND-100/
scaffold:
ifdef IS_WIN
	@echo === [2/3] Scaffold ND-100/ from template
	@if not exist "$(SRC_TPL)/build.gradle" (echo ERROR: missing template at $(SRC_TPL) & exit 1)
	@if not exist "$(OUT)" mkdir "$(OUT)"
	@copy /Y "$(SRC_TPL)/build.gradle"         "$(OUT)" >nul
	@copy /Y "$(SRC_TPL)/settings.gradle"      "$(OUT)" >nul
	@copy /Y "$(SRC_TPL)/extension.properties" "$(OUT)" >nul
	@copy /Y "$(SRC_TPL)/Module.manifest"      "$(OUT)" >nul
	@copy /Y "$(SRC_TPL)/gradlew.bat"          "$(OUT)" >nul
	@if exist "$(SRC_TPL)/gradlew" copy /Y "$(SRC_TPL)/gradlew" "$(OUT)" >nul
	@xcopy /Y /S /I /E /Q "$(SRC_TPL)/gradle" "$(OUT)/gradle" >nul
	@xcopy /Y /S /I /E /Q "$(SRC_TPL)/src"    "$(OUT)/src"    >nul
else
	@echo "=== [2/3] Scaffold ND-100/ from template"
	@[ -f "$(SRC_TPL)/build.gradle" ] || { echo "ERROR: missing template at $(SRC_TPL)"; exit 1; }
	@mkdir -p "$(OUT)"
	@cp -f "$(SRC_TPL)/build.gradle"         "$(OUT)/"
	@cp -f "$(SRC_TPL)/settings.gradle"      "$(OUT)/"
	@cp -f "$(SRC_TPL)/extension.properties" "$(OUT)/"
	@cp -f "$(SRC_TPL)/Module.manifest"      "$(OUT)/"
	@cp -f "$(SRC_TPL)/gradlew.bat"          "$(OUT)/"
	@if [ -f "$(SRC_TPL)/gradlew" ]; then cp -f "$(SRC_TPL)/gradlew" "$(OUT)/" && chmod +x "$(OUT)/gradlew"; fi
	@cp -rf "$(SRC_TPL)/gradle" "$(OUT)/"
	@cp -rf "$(SRC_TPL)/src"    "$(OUT)/"
endif
	@$(MAKE) -s inject-version

## inject-version: write MODULE_VERSION into extension.properties (internal)
inject-version:
ifdef IS_WIN
	@echo === Injecting MODULE_VERSION=$(MODULE_VERSION) into extension.properties
	@powershell -NoProfile -Command "(Get-Content '$(OUT)/extension.properties') -replace '@moduleversion@', '$(MODULE_VERSION)' | Set-Content '$(OUT)/extension.properties'"
else
	@echo "=== Injecting MODULE_VERSION=$(MODULE_VERSION) into extension.properties"
	@sed -i.bak 's/@moduleversion@/$(MODULE_VERSION)/g' "$(OUT)/extension.properties"
	@rm -f "$(OUT)/extension.properties.bak"
endif

# ---------------------------------------------------------------------------
# Gradle build
# ---------------------------------------------------------------------------
## gradle: run gradle buildExtension (no codegen)
gradle: check-ghidra
ifdef IS_WIN
	@echo === [3/3] Gradle buildExtension
	@if not exist "$(OUT)/gradlew.bat" (echo ERROR: $(OUT)/gradlew.bat not found. Run 'make scaffold' first. & exit 1)
	cd /d "$(OUT)" && $(GRADLEW) --no-daemon clean buildExtension
	@echo === Done. Extension ZIP under $(OUT)/dist
	@dir /b "$(OUT)/dist/ghidra_*_ND-100.zip" 2>nul
else
	@echo "=== [3/3] Gradle buildExtension"
	@[ -x "$(OUT)/gradlew" ] || [ -f "$(OUT)/gradlew.bat" ] || { echo "ERROR: $(OUT)/gradlew not found. Run 'make scaffold' first."; exit 1; }
	cd "$(OUT)" && $(GRADLEW) --no-daemon clean buildExtension
	@echo "=== Done. Extension ZIP under $(OUT)/dist/"
	@ls -1 "$(OUT)/dist/"ghidra_*_ND-100.zip 2>/dev/null || true
endif

## gradle-only: scaffold + gradle (skip codegen)
gradle-only: check-ghidra scaffold gradle

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
## clean: remove gradle build outputs
clean:
ifdef IS_WIN
	@if exist "$(OUT)/dist"    rmdir /S /Q "$(OUT)/dist"
	@if exist "$(OUT)/build"   rmdir /S /Q "$(OUT)/build"
	@if exist "$(OUT)/.gradle" rmdir /S /Q "$(OUT)/.gradle"
else
	rm -rf "$(OUT)/dist" "$(OUT)/build" "$(OUT)/.gradle"
endif

## distclean: clean + drop scaffolded ND-100/ contents
distclean: clean
ifdef IS_WIN
	@if exist "$(OUT)/src"    rmdir /S /Q "$(OUT)/src"
	@if exist "$(OUT)/gradle" rmdir /S /Q "$(OUT)/gradle"
	@if exist "$(OUT)/build.gradle"         del /Q "$(OUT)/build.gradle"
	@if exist "$(OUT)/settings.gradle"      del /Q "$(OUT)/settings.gradle"
	@if exist "$(OUT)/extension.properties" del /Q "$(OUT)/extension.properties"
	@if exist "$(OUT)/Module.manifest"      del /Q "$(OUT)/Module.manifest"
	@if exist "$(OUT)/gradlew"              del /Q "$(OUT)/gradlew"
	@if exist "$(OUT)/gradlew.bat"          del /Q "$(OUT)/gradlew.bat"
else
	rm -rf "$(OUT)/src" "$(OUT)/gradle"
	rm -f  "$(OUT)/build.gradle" "$(OUT)/settings.gradle" \
	       "$(OUT)/extension.properties" "$(OUT)/Module.manifest" \
	       "$(OUT)/gradlew" "$(OUT)/gradlew.bat"
endif
