# Original full26 installer matrix on generic ARM

Actual [38956150348](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38956150348), source `10fb6c2253fef92f5ba55d85740a06dc278a3d87`, passed all26 original selected methods and22 worker transaction calls, with zero errors, failures or skips. The fresh native producer, package integration, class cleanup, guest retirement, private-workspace removal and all five VM owner cleanup receipts pass. The guest completed naturally in388.017seconds.

Overall execution remains **FAIL**: final outer cleanup could not inspect the producer image. The retained daemon log explicitly reports `No such image`; the deleting operation was not exported. Automatic pruning is a source-supported inference because the producer was untagged and the original integration removes its child without `--no-prune`.

The implemented correction gives each producer a unique, collision-checked run-token tag. Final cleanup verifies its image identity, sole tag and ownership label, removes that tag with `--no-prune` after consumer retirement, and checks producer/tag absence plus preservation of borrowed images. All14 private engine files, original methods, signature checks, resource limits and deadlines remain unchanged. All27 focused inert controls pass; the corrected actual retry is pending.

Producer `b07259bc63d7d58298a03bbb406d685b20e5c8a4` and retained tooling `9c1fa9e6674ce24edb9655a56436d4c5c0985c54` preserve the existing exact inputs. Local collection: `artifacts/development/installer-full26-run38956150348`; archive SHA256 `36aa08955e1f3ae91a54e649c9e7431fb89b36513a8e757773dddb10e376e43a`, logs `7391aa940d1e822f1cbdabb8cb71fd98ddf6dac9e4f640158fadfa189e06f7db`. Root reran the27 controls and immutable retained-file/original-engine joins.

This covers disposable generic ARM execution. The native-container P0 proc-mount failure remains separate; physical M2 installation, boot recovery, platform compatibility and release admission remain NOT RUN.
