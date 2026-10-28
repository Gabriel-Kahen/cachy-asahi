#!/bin/bash
# SPDX-License-Identifier: MIT
# Intended only for the unchanged standard build.py/container-entry.sh path.
set -Eeuo pipefail
stage=prereqs
probe=
trap 'code=$?; if (( code != 0 )); then [[ -z $probe ]] || printf "LSP_PROBE %s FAIL\n" "$probe"; printf "LSP_STAGE %s FAIL\n" "$stage"; fi' EXIT
printf '%s\n' 'LSP_STAGE prereqs START'
[[ $# == 2 ]] || { echo 'usage: lsp-native-build.sh SOURCE NEW_EVIDENCE' >&2; exit 2; }
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && $(id -u) != 0 && $(uname -s) == Linux && $(uname -m) == aarch64 ]] || {
  echo 'standard nonroot native Linux ARM builder required' >&2; exit 2;
}
source_dir=$(realpath -e -- "$1")
evidence=$2
[[ $source_dir == /* && $evidence == /* && -d $source_dir && ! -e $evidence ]] || exit 2
cd "$source_dir"
[[ ! -e .config.mk && ! -e .build && -f project.mk ]] || { echo 'fresh source tree required' >&2; exit 2; }
mkdir -- "$evidence"
for tool in gcc g++ make pkg-config readelf timeout install sha256sum; do
  command -v "$tool"
done
probe=compiler
gcc -v > "$evidence/gcc.txt" 2>&1
g++ -v > "$evidence/gxx.txt" 2>&1
[[ $(gcc -dumpmachine) == aarch64* ]] || { echo 'native aarch64 compiler required' >&2; exit 2; }
printf '%s\n' 'LSP_PROBE compiler PASS'
probe=pkgconf
pkg-config --version > "$evidence/pkgconfig.txt"
printf '%s\n' 'LSP_PROBE pkgconf PASS'
probe=cairo
pkg-config --exists cairo
printf '%s\n' 'LSP_PROBE cairo PASS'
probe=sndfile
pkg-config --exists sndfile
printf '%s\n' 'LSP_PROBE sndfile PASS'
pkg-config --modversion cairo sndfile > "$evidence/pkgconfig-versions.txt"
probe_flags=$(pkg-config --cflags cairo sndfile)
read -r -a header_flags <<< "$probe_flags"
probe=headers
printf '#include <cairo.h>\n#include <sndfile.h>\n#include <pthread.h>\n#include <dlfcn.h>\n' |
  timeout --signal=TERM --kill-after=10s 30s gcc -march=armv8-a -mtune=generic \
    "${header_flags[@]}" -x c -fsyntax-only -
printf '#include <vector>\n#include <cstdint>\n' |
  timeout --signal=TERM --kill-after=10s 30s g++ -march=armv8-a -mtune=generic -x c++ -fsyntax-only -
printf '%s\n' 'LSP_PROBE headers PASS'
probe=
printf '%s\n' 'LSP_STAGE prereqs PASS'

# Let upstream append its common flags; remove inherited tuning/optimization.
stage=config
printf '%s\n' 'LSP_STAGE config START'
env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u HOST_CFLAGS -u HOST_CXXFLAGS -u HOST_LDFLAGS \
  timeout --signal=TERM --kill-after=20s 120s make config VERBOSE=1 FEATURES=lv2 \
    PLATFORM=Linux ARCHITECTURE=aarch64 \
    ARCHITECTURE_CFLAGS='-march=armv8-a -mtune=generic' \
    HOST_ARCHITECTURE_CFLAGS='-march=armv8-a -mtune=generic' CC=gcc CXX=g++ PREFIX=/usr
cp -- .config.mk "$evidence/config.mk"
# Parse selected data only; never source or eval generated configuration.
declare -A selected_config=()
while IFS='=' read -r key value; do
  case "$key" in
    BUILD_FEATURES|CFLAGS|CXXFLAGS|HOST_CFLAGS|HOST_CXXFLAGS|SO_FLAGS|HOST_SO_FLAGS)
      [[ ! -v selected_config[$key] && ${#value} -le 2048 && $value != *$'\r'* ]] || exit 2
      read -r -a words <<< "$value"
      selected_config[$key]="${words[*]}"
      ;;
  esac
done < .config.mk
for key in BUILD_FEATURES CFLAGS CXXFLAGS HOST_CFLAGS HOST_CXXFLAGS SO_FLAGS HOST_SO_FLAGS; do
  value=${selected_config[$key]:-}
  [[ -n $value ]] || exit 2
  if [[ $key == BUILD_FEATURES ]]; then
    [[ $value == lv2 ]] || exit 2
  else
    read -r -a words <<< "$value"
    for word in "${words[@]}"; do
      case "$word" in
        *-flto*|-mcpu=*) exit 2 ;;
        -march=*) [[ $word == -march=armv8-a ]] || exit 2 ;;
        -mtune=*) [[ $word == -mtune=generic ]] || exit 2 ;;
      esac
    done
    case "$key" in
      CFLAGS|CXXFLAGS|HOST_CFLAGS|HOST_CXXFLAGS)
        [[ " $value " == *' -march=armv8-a '* && " $value " == *' -mtune=generic '* ]] || exit 2 ;;
    esac
  fi
done
for key in BUILD_FEATURES CFLAGS CXXFLAGS HOST_CFLAGS HOST_CXXFLAGS SO_FLAGS HOST_SO_FLAGS; do
  printf 'LSP_CONFIG %s %s\n' "$key" "${selected_config[$key]}"
done
printf '%s\n' 'LSP_STAGE config PASS'
stage=build
printf '%s\n' 'LSP_STAGE build START'
timeout --signal=TERM --kill-after=20s 1800s make -j2 VERBOSE=1
library=.build/target/lsp-plugin-fw/lsp-plugins-lv2.so
[[ -f $library && -f .build/target/lsp-plugin-fw/plugins.json ]]
readelf -W -h -l -d "$library" > "$evidence/lv2-elf.txt"
sha256sum "$library" .build/target/lsp-plugin-fw/plugins.json > "$evidence/build-output.sha256"
cat "$evidence/gcc.txt" "$evidence/gxx.txt" "$evidence/pkgconfig-versions.txt" \
  "$evidence/config.mk" "$evidence/lv2-elf.txt" "$evidence/build-output.sha256"
printf '%s\n' 'LSP_STAGE build PASS'
printf '%s\n' 'LSP build completed; package/ELF/pair checks remain with build.py and compare.py; hardware NOT RUN'
