#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
if (( $# != 2 )) || [[ $1 != /* || $2 != /* || $1 == / ]]; then
    printf 'usage: %s ABSOLUTE_STAGE_ROOT ABSOLUTE_SCRATCH_DIRECTORY\n' "$0" >&2
    exit 2
fi
stage=$(realpath -e -- "$1")
mkdir -p -- "$2"
scratch=$(mktemp -d "$2/md4c-smoke.XXXXXXXX")
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export PKG_CONFIG_LIBDIR="$stage/usr/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$stage"
unset PKG_CONFIG_PATH
export LD_LIBRARY_PATH="$stage/usr/lib"
for name in md4c md4c-html; do
    [[ $(pkg-config --modversion "$name") == 0.5.3 ]]
    [[ $(readlink "$stage/usr/lib/lib$name.so") == "lib$name.so.0" ]]
    [[ $(readlink "$stage/usr/lib/lib$name.so.0") == "lib$name.so.0.5.3" ]]
    soname=$(readelf -d "$stage/usr/lib/lib$name.so.0.5.3" | awk '/\(SONAME\)/ {print $NF}')
    [[ $soname == "[lib$name.so.0]" ]]
done
printf '0.5.3\n' > "$scratch/version.expected"
"$stage/usr/bin/md2html" --version > "$scratch/version.actual"
cmp "$scratch/version.expected" "$scratch/version.actual"
printf '# hello\n\n*world* & text\n' > "$scratch/input.md"
printf '<h1>hello</h1>\n<p><em>world</em> &amp; text</p>\n' > "$scratch/output.expected"
"$stage/usr/bin/md2html" < "$scratch/input.md" > "$scratch/output.actual"
cmp "$scratch/output.expected" "$scratch/output.actual"
# pkg-config output is deliberately split into compiler arguments.
read -r -a flags <<< "$(pkg-config --cflags --libs md4c-html md4c)"
"${CC:-cc}" -std=c99 -Wall -Wextra -Werror "$here/smoke.c" "${flags[@]}" -o "$scratch/api-smoke"
"$scratch/api-smoke"
mkdir "$scratch/consumer"
cp "$here/smoke.c" "$scratch/consumer/smoke.c"
cat > "$scratch/consumer/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.12)
project(md4c_consumer C)
find_package(md4c CONFIG REQUIRED NO_DEFAULT_PATH PATHS "${STAGED_MD4C}")
add_executable(api-smoke smoke.c)
target_link_libraries(api-smoke PRIVATE md4c::md4c-html md4c::md4c)
CMAKE
cmake -S "$scratch/consumer" -B "$scratch/consumer-build" \
    -DSTAGED_MD4C="$stage/usr/lib/cmake/md4c"
cmake --build "$scratch/consumer-build"
"$scratch/consumer-build/api-smoke"
printf 'md4c 0.5.3 staged CLI, C API, pkg-config, CMake and SONAME smoke PASS\n'
