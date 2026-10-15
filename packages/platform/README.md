# Platform build-only candidates

This directory holds separately reviewed Asahi platform build candidates. It is
outside the ordinary desktop/shell/settings overlay discovery scope. Directory
placement does not permit installation, repository publication, or replacement
of the working Asahi platform stack.

The initial candidates are `asahi-audio` 4.1-2 and `alsa-ucm-conf-asahi` 10-2.
Their fixed source inputs and data payloads are checked only by
`scripts/ci/asahi-audio-data/run.py` and its adjacent input/payload maps. This
build-only caller retains runtime dependency metadata, uses `--nodeps` for the
isolated construction step, and requires exact payload bytes, paths, modes and
ownership. Its exported reports retain the ordinary protected-name/payload
rejections. Other errors are fatal.

The generic recipe and package protections remain unchanged. The ordinary
builder, original-four locks, complete-development composition and release
selection do not include these candidates. Adding another platform recipe here
does not extend the fixed two-package caller.

A native build or byte comparison proves package construction only. Runtime
dependency resolution, installation/removal, audio and speaker-protection
behavior, coordinated platform updates, and both supported M2 Air sizes require
separate validation. Release selection remains false.
