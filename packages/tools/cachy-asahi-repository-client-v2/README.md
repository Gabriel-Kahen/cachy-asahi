# cachy-asahi-repository-client-v2 0.1.0-1

An explicitly selected MIT source companion to exact cachy-asahi-repository-runtime 0.1.0-1. It installs only the additional client_v2.py helper at /usr/share/cachy-asahi/repository-runtime/scripts/client/client_v2.py, plus its own documentation/pins/license. The existing runtime retains ownership and exact bytes of client.py, release.py and source_delivery.py. No file overlaps, caller switch, executable wrapper, service or hook is added; existing Apps' exact runtime dependency remains satisfied.

Invoke the additional source explicitly:

```sh
python3 -B /usr/share/cachy-asahi/repository-runtime/scripts/client/client_v2.py --help
python3 -B /usr/share/cachy-asahi/repository-runtime/scripts/client/client_v2.py sources --help
```

The exact sibling scripts/release/source_delivery.py is supplied by the existing runtime. This two-package layout supports lookup/export without a checkout; copying client_v2.py alone is unsupported. Valid tilde package versions such as `1.0~rc1-1` use existing development envelope/source-delivery formats. Signature/expiry/namespace/path/provenance/source-association/payload checks remain intact. Sources lookup/export never advances a checkpoint or grants legal/source-completeness/native/hardware/public/stable acceptance.

The arch=any package depends on Python 3.11+ and exact repository-runtime 0.1.0-1; its existing runtime supplies GPG, libarchive and pacman requirements. No package/trust/system configuration is modified by research checks. Package/check inputs include an unchanged TEST fixture and staging controls, which are never installed. Run check_source.py --recipe-root /absolute/recipe and --stage /absolute/companion-only-stage for exact nine-source/six-payload checks. test_runtime.py can stage the actual existing runtime recipe with --runtime-recipe-root; otherwise it verifies/copies the three read-only installed dependency helper files into its owned temporary fixture before staging the companion.

Local staging/TEST-key controls are not a native clean build pair, signed/ALPM installed lifecycle, M2 result or release admission. Existing Runtime and Apps recipes/pins remain unchanged. Root owns new development-inventory/native-build/tooling registration and any future publication/admission.
