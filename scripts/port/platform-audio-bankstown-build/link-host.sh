#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Explicit host-diagnostic linker bound; Rust1.96.1 selects bundled LLD.
exec /usr/bin/cc -Wl,--threads=1 "$@"
