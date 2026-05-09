#!/usr/bin/env sh

#
# Copyright © 2015-2021 the original authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

##############################################################################
#
#   Gradle startup script for POSIX-ish shells (sh/bash/zsh).
#   Pairs with gradlew.bat for Windows.
#
##############################################################################

set -e

# Resolve symlinks to find the script's real directory.
PRG="$0"
while [ -h "$PRG" ]; do
    ls=$(ls -ld "$PRG")
    link=$(expr "$ls" : '.*-> \(.*\)$')
    if expr "$link" : '/.*' > /dev/null; then
        PRG="$link"
    else
        PRG=$(dirname "$PRG")"/$link"
    fi
done
APP_HOME=$(cd "$(dirname "$PRG")" && pwd -P)

DEFAULT_JVM_OPTS="-Xmx64m -Xms64m"

# Locate Java.
if [ -n "$JAVA_HOME" ]; then
    if [ -x "$JAVA_HOME/jre/sh/java" ]; then
        JAVACMD="$JAVA_HOME/jre/sh/java"
    else
        JAVACMD="$JAVA_HOME/bin/java"
    fi
    if [ ! -x "$JAVACMD" ]; then
        echo "ERROR: JAVA_HOME points at an invalid directory: $JAVA_HOME" >&2
        exit 1
    fi
else
    JAVACMD=java
    if ! command -v java >/dev/null 2>&1; then
        echo "ERROR: JAVA_HOME is not set and no 'java' command was found in PATH." >&2
        exit 1
    fi
fi

CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"

# Translate POSIX paths to Windows format when running under Cygwin/MSYS so the JVM is happy.
case "$(uname)" in
    CYGWIN*|MINGW*|MSYS*)
        APP_HOME=$(cygpath --path --mixed "$APP_HOME" 2>/dev/null || echo "$APP_HOME")
        CLASSPATH=$(cygpath --path --mixed "$CLASSPATH" 2>/dev/null || echo "$CLASSPATH")
        ;;
esac

# shellcheck disable=SC2086
exec "$JAVACMD" $DEFAULT_JVM_OPTS $JAVA_OPTS $GRADLE_OPTS \
    "-Dorg.gradle.appname=$(basename "$0")" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain "$@"
