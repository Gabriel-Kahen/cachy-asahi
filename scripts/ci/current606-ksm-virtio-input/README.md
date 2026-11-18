# Current606 generic16K KSM and virtio-input build

The derivative uses the exact Current606 R5 KSM media at commit `5a643db838759d7cf574e596efbcd45b1df96984`, tree `f678cbc8338c0e0a29c09be08de8f5c6830e6741`. `base.config` and `base-build-receipt.json` are public retained R5 leaves. `build_kernel.py` derives from the retained KSM helper at SHA-256 `7372ebfece249fae202652f3c3bb419f730bd0e466dc076907270dac1ac873ed`. The only Kconfig delta enables built-in `CONFIG_VIRTIO_INPUT`. The source archive's virtio-input dependencies are `VIRTIO` and `INPUT`, both built in on R5. It selects no additional symbols. KSM, advice syscalls, 16KiB pages, evdev, both virtio buses, and the module-free policy remain in the exact config.

Use the local composite action from the owning `ubuntu-24.04-arm` job on the exact manually selected source and original attempt. Set `work` to the fresh `keyboard-kernel` child inside the job's existing state directory under `RUNNER_TEMP`.

```yaml
- uses: ./.github/actions/current606-ksm-virtio-input
  with:
    source-sha: ${{ github.sha }}
    work: ${{ runner.temp }}/gui606-state/keyboard-kernel
```

The action follows the original disposable-runner package provisioning commands. The lane compares actual native Ubuntu LLVM18 and supporting tool bytes and paths against the accepted R5 build receipt before acquiring the archive. It uses the existing bounded Current604 acquisition and KSM controller, and checks the generated config byte-for-byte before compiling. The original 262,965,559-byte archive has SHA-256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad` and Linux source revision `94fb23346d522edf53722357c426a3e58030beea`.

A consumer in the same job can point `verify.py --output` at the `built` directory. It rechecks the two command logs, receipt, exact config, AArch64 16KiB Image header and virtio-input symbols in the linked `System.map`. It emits the 13-field `KSM_ADVICE_VIRTIO_INPUT_GENERIC16K_DIAGNOSTIC_V1` profile with release `7.1.13-generic16k-managed-gui`. Profile, Image, config and receipt roles are relative to `work`.

| Role | Path |
| --- | --- |
| Profile | `kernel-profile.json` |
| Image | `built/build/arch/arm64/boot/Image` |
| Config | `built/build/.config` |
| Build receipt | `built/build-receipt.json` |
| Linked symbol map | `built/build/System.map` |
| Kernel command logs | `built/configure.log`, `built/build.log` |
| Owner and controller | `owner.json`, `controller.json`, `controller.stdout`, `controller.stderr` |

Build evidence stays inside the owning job. Image, config and build logs are available to its consumer before the job retires. The action emits a fixed status and has no artifact upload, public media transport, boot, install, or signing step. Build success does not qualify emulated boot, a desktop seat, native hardware or release.
