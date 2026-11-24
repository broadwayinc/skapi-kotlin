#!/usr/bin/env bash
# Builds skapi-kotlin and runs tests/ReferencingOwnerRights.java against it (Java 11 or later).
# The dependency jars are taken from the Gradle cache the build fills. No network calls at run time.
set -euo pipefail
cd "$(dirname "$0")/.."

./gradlew -q ${GRADLE_ARGS:-} :skapi:jar   # GRADLE_ARGS=--offline to build from the cache only
VERSION=$(sed -n 's/.*version = "\(.*\)".*/\1/p' build.gradle.kts | head -1)
JAR="skapi/build/libs/skapi-kotlin-$VERSION.jar"

CACHE="${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1"
dep() { find "$CACHE" -name "$1" | head -1; }
CP="$JAR"
for j in kotlin-stdlib-2.0.21.jar kotlinx-serialization-core-jvm-1.7.3.jar kotlinx-serialization-json-jvm-1.7.3.jar \
         kotlinx-coroutines-core-jvm-1.8.1.jar okhttp-4.12.0.jar 'okio-jvm-3.*.jar'; do
    p=$(dep "$j")
    if [ -z "$p" ]; then echo "missing $j in $CACHE (run a Gradle build once)" >&2; exit 1; fi
    CP="$CP:$p"
done

exec java -cp "$CP" tests/ReferencingOwnerRights.java
