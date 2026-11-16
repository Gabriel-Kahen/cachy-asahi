# Owned local-volume private-bind successor v14

Source/DATA implementation only; Docker/native execution NOT RUN. Source351/run43928150645 remains consumed and unchanged. The curated kernel `/work` row contains `master:1`; its strict preentry proof correctly refuses before tools. Prestart ExitCode0 does not mean runtime success (actual start--attach returned1). The two curated fixtures are the only Original-derived files used here.

Docker [volume propagation is not configurable](https://docs.docker.com/engine/storage/volumes/); [bind mounts support explicit bind-propagation](https://docs.docker.com/engine/storage/bind-mounts/). This successor changes SETUP, preserving the complete actor/kernel-helper bytes and all private/no-shadow/root/device/source/EROFS checks. It never accepts slave/master propagation.

The same freshly owned, labelled, default-local named volume remains the lifecycle object. Immediately before actor construction, a fixed local Unix-daemon query projects EXACTLY ID,DockerRootDir,OSType,Architecture,CgroupVersion,SecurityOptions,OperatingSystem (<=1MiB). Rootful Linux/native/cgroupv2 and the existing daemon ID/root must match; DockerDesktop managed-path semantics and remote/default contexts refuse. A hosted native ARM cloud VM remains the existing reference; no physical-machine/M2 inference is added. No proxy/registry/env fields are queried into this new proof; preexisting daemon.json is unchanged.

The exact one-row volume inspection (<=64KiB) must have owned name/labels, Driver=local,Scope=local, empty options, and a canonical Mountpoint equal to this inspected DockerRootDir/volumes/owned-name/_data. Ordinary controller traversal of Docker-managed directories is neither assumed nor performed. The daemon resolves its own API-managed path through --mount type=bind; missing daemon-side directories refuse, with no create-source fallback. Only that directory and its fixed build/stage0 descendant become writable `/work` and readonly `/stage0`,`/work/build/stage0` binds. Every source/input/material bind is also explicitly rprivate. Init retains capCHOWN only and exact empty-directory/inode initialization. No host chmod/chown/mount, arbitrary path, remote driver/options, privilege or resource increase is added.

`qualification/controller.json` and `rust-build/producer.json` retain `owned_work_bind`:

- schema14/status API_OWNED_LOCAL_VOLUME_BIND_DERIVATION_ONLY; endpoint unix:///var/run/docker.sock;
- daemon_inspect and volume_inspect each `{json,pin:{bytes,sha256}}`, preserving exact bounded API stdout;
- volume,labels,daemon_root,work_source,stage0_source,bind_propagation=rprivate,native_acceptance=false,holds_preserved=true.

The same receipt is carried by the returned qualification object; its existing qualification_controller descriptor and unchanged phase transfer retain it. Qualification validation replays the API derivation; the independent v14 Reader is owned separately. API configuration is not kernel proof. The unchanged c5f732… mount helper still runs before workspace writes/tools and validates complete kernel observations; readonly aliases must also pass actual EROFS checks. All entry/admission/workflow/HTTP/resource/conditional-transfer/108-hold bodies and predicates remain unchanged.

`prepare.py --parent CLOSED_SOURCE351 --profile-sha256 HASH --output FRESH` constructs only an unissued files-only successor. Its full byte/mode inverse restores351; preserved v13/v12 constructors then restore344 and340. Actual Source/ref/run/job/image/artifact/approval and Root grants remain NULL. Constructor code is not an operational actor.

Run focused controls with isolated Python3.12/3.14:

```
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v14/test_data.py
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v14/test_runtime.py
```

MODEL controls exercise actual generators and both maintained setup drivers through qualified binds/init/inspection to an explicit cap0 actor boundary, then exact owned cleanup; no Docker process is launched. They cover unowned/remote/Rootless/malformed roots/options, wrong access/propagation/source/shadows, raw-proof tampering, unchanged kernel rejection of curated master:1 and private MODEL kernel positives. Passing models do not establish daemon-host path availability or future native success. A daemon that cannot resolve its inspected local default-volume directory is a concrete runtime HOLD; no hostpath or privilege fallback exists.
