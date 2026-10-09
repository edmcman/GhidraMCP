#!/usr/bin/env bash
# Run after ./gradlew buildExtension with GHIDRA_INSTALL_DIR set.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to a Ghidra installation}"
test -f build/libs/GhidraMCP.jar
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
classpath="$PWD/build/libs/GhidraMCP.jar"
# Exclude installed extensions so the checks always use this build.
while IFS= read -r jar; do
    classpath="$classpath:$jar"
done < <(rg --files "$GHIDRA_INSTALL_DIR/Ghidra" "$PWD/lib" -g '*.jar' | rg -v '/Extensions/')
javac -proc:none -cp "$classpath" -d "$test_dir" tests/DataItemTypesTest.java
XDG_CONFIG_HOME="$test_dir/config" XDG_CACHE_HOME="$test_dir/cache" \
    java -Duser.home="$test_dir" -Djava.awt.headless=true -cp "$test_dir:$classpath" \
    DataItemTypesTest "$GHIDRA_INSTALL_DIR"
