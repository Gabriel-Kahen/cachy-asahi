# Fish r12 native check-log retention

The hosted Fish 0.1.0-2 build names its package archive
`cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz` and its makepkg check log
`cachy-asahi-fish-config-0.1.0-2-aarch64-check.log`. The r12 constructor
updates the two required check-log paths in the public exporter and policy.
The existing recipe, workflow, ownership checks, resource limits, and
historical source constructors retain their pinned bytes.

Use the complete published r11 readback as the input.

```sh
python3 -I -B scripts/ci/fish-config02-native-source/successor_v12/prepare.py \
  --base /absolute/r11-public-readback --output /absolute/fresh-output
```

The output reproduces the 70-file r12 tree
`de61a2e7351a09d1dcf0471d50c80e3a1a6ee479` and restores every r11 byte
through the inverse check. Actual publication and native admission use
separate Root inputs.

Pass the r11 readback and retained R127 Original to `test_data.py --base
/absolute/r11-public-readback --original /absolute/public-evidence.Original.archive`.
The test recovers each omitted check log from its retained build log and
checks the bytes against the original semantic receipt before re-export.
