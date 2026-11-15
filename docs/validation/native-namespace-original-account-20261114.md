# Namespace diagnostic: original alarm account, 2026-11-14

The failed observable diagnostic exposed an incorrect identity expectation
before either namespace command. Published Source
`69455e13bc99a2b2b6c2aca11f69d581769ae500`, run43662248024/attempt1,
job132653893886, required alarm/process UID/GID1000. Its actual original bootstrap
sets **alarm1001:1001**, matching the retained native runner UID/GID1001.
This proves an identity mismatch, not namespace support or a policy denial.
The failure and all closed preflight/native/Original roles remain unchanged.

The [context correction README](../../scripts/ci/native-build-namespace-context/README.md)
and `observed-mismatch.json` bind the selected ordinary DATA fixtures:

| Original logical operand | Bytes | SHA256 |
| --- | ---: | --- |
| `bootstrap-proof/bootstrap-Dockerfile` |1093| `929b167a1e3779742aba1b248d3f09c948c93fd35b5bdfe3f021bb8b37174f4b` |
| `bootstrap-proof/bootstrap-runner.json` |4075| `4fdbd94082e73397ea56f3ef6c20b36116dcab6178c3224f53eac93c7fa524a4` |
| `actor-logs/0025.log` |7503| `5b8915fd1c9673f04dbec49dacce6d9b51b29fd1ab4c0b55e190277088a9e9da` |

The Dockerfile explicitly executes `groupmod -g 1001 alarm` and
`usermod -u 1001 -g alarm alarm`, then selects `USER alarm` and `WORKDIR /tmp`.
The traceback identifies a composite pre-probe guard. The actual Python
PID/PPID, cwd and whole-byte349 baseline equality were not individually emitted;
they remain unknown. Root's passive inspection verified all87 mapped file bodies
of the retained failure capsule. These fixtures permit review without reopening
that Original ZIP or invoking a full Reader.

## Minimal published successor

Root published Source `3937d8b9f3210f4e9868bf19f01dfa22de64ddfe` at
`refs/heads/codex/native-build-namespace-alarm1001-v1-20261114`, with sole parent
Source69455 and tree `f1757dbedeed1591cdb8538f6c91e493cd451966`.
The retained publication record is
`artifacts/development/orchestrator-resume-20261114/original-alarm1001-source-family-r1/Root-published-source-full200.json`,
50,625 bytes, SHA256
`b522b296a2b302312df9ef93b88e8ea90e1a40fa3eb7be6eb976bfa21c025811`.
It records full200 body/mode/blob joins. Comparison with the retained parent
confirms exactly six changed bodies, with194 unchanged:

- `native/build-tools-contract-v2.json`: exact UID/GID1001.
- `native/build_tools_alpm_v2.py`: exact outer/account1001 and private-home owner.
- `native/build_tools_tools_v2.py`: outer/bubblewrap1001; mapped-root unshare
  remains0 with exact UID/GID maps `[[0,1001,1]]`.
- `native/build_tools_projection_v2.py`: affected producer/contract pins.
- `native/build_tools_reader_v2.py`: matching independent expectations and pins.
- `native/source-map.json`: complete map reseal, SHA256
  `0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e`.

The matching Reader is106,215 bytes, SHA256
`58b258fde9c49aca7f8d4e8b7e61358f175da8650547df64dc96891c2e33b5cf`.
Bootstrap/account bytes, Dockerfile generators, probe argv,349 baseline,
normal Docker image-build `RUN USER alarm`, architecture/PID/cwd guards,
privacy/resource/retirement rules and canonical
`HEAVY_NON_KERNEL`/`native-arm-build` route remain held. There is no account
normalization, identity range, fallback or policy bypass.

## Next gate

Source publication is DATA qualification only. Its publication record leaves
factory Main proof and resource authority NULL and records corrected-Source
Native POSTs, Original GETs, Reader calls and Source execution all0.
Root must bind the new source/map/Reader tuple to genuine factory CI/Main evidence,
fresh identity/resource authority and fresh once roles before any actual trial.
Do not replay Source69455's failed run or closed intake roles. Corrected native
execution, namespace outcomes, M2 and release acceptance remain **NOT RUN**.
This documentation pass read selected DATA only and executed no Source/Reader.
