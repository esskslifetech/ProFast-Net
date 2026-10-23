#!/usr/bin/env bash
# Builds the native core, runs its tests, and reports what the host supports.
#
#   ./scripts/build.sh
#   ./scripts/build.sh --python        # also install the CLI editable
#   ./scripts/build.sh --clean

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="$root/build/native"
configuration="Release"
with_python=0
clean=0

for arg in "$@"; do
    case "$arg" in
        --python) with_python=1 ;;
        --clean) clean=1 ;;
        --debug) configuration="Debug" ;;
        -h|--help)
            sed -n '2,6p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

if [ "$clean" -eq 1 ] && [ -d "$build" ]; then
    echo "removing $build"
    rm -rf "$build"
fi

generator=()
if command -v ninja >/dev/null 2>&1; then
    generator=(-G Ninja)
fi

echo "== configure ($configuration)"
cmake -S "$root/native" -B "$build" "${generator[@]}" "-DCMAKE_BUILD_TYPE=$configuration"

echo "== build"
cmake --build "$build" --config "$configuration" --parallel

bench="$build/bin/pfbench"

echo "== known-answer vectors"
"$bench" selftest

echo "== native tests"
ctest --test-dir "$build" -C "$configuration" --output-on-failure

echo "== environment"
"$bench" bench

if [ "$with_python" -eq 1 ]; then
    echo "== python control plane"
    python3 -m pip install --upgrade pip
    # Quoting the extras keeps zsh from globbing the brackets.
    python3 -m pip install -e "$root/python[dev]"
    ( cd "$root" && python3 -m pytest -q python )
fi

echo
echo "done. try:"
echo "  $bench selftest"
echo "  python3 -m profast.cli --embedded status"
