# Owned VM numeric ownership adapter

This fixture-only route preserves six numeric group-owned records in four exact
signed archives. The profile authorizes each by package name, version, archive
SHA256, path, tar type, UID, GID, mode and size. The existing duplicate, sparse,
special-node, hardlink closure, overlap, parent-alias and resource checks remain.
Unknown nonroot records and root-flattened replacements refuse admission.

The exact required UID is 0; required GIDs are 0, 5, 11, 50, 81 and 102. The
existing single-ID route cannot represent these groups. An explicit profile
purpose `full-installer-owned-vm-numeric-groups-v1` selects this closed mapping:

| Inner ID | Outside VM ID |
| --- | --- |
| UID 0 | UID 23001 |
| GID 0 | GID 23001 |
| GID 5 | GID 23005 |
| GID 11 | GID 23011 |
| GID 50 | GID 23050 |
| GID 81 | GID 23081 |
| GID 102 | GID 23102 |

The existing root service in the disposable generic ARM VM creates this user
namespace for ordinary UID23001. It refuses occupied reserved outside group IDs.
It writes the exact maps, checks `setgroups=allow`, kills and reaps its bounded
namespace creator, and retains only the namespace FD and a root-protected lease.
No standing privileged helper or root broker receives requests from the engine.
The lease binds the selected profile hash, nonce and namespace device/inode.

The root service's closed-FD launcher passes this exact typed namespace FD
through the held ELF/setpriv chain. The ordinary parent remains UID/GID23001,
empty supplementary groups, NNP1, and zero effective/permitted/inheritable/
ambient/bounding capabilities. A typed FD transfer preserves the sealed engine
spec and exact evidence directory. The child enters the retained user namespace,
closes that FD and uses the same mount/PID/proc/network namespace launch.

The shared installer core accepts the numeric mapping only with its exact
fixture purpose, actual generic4K ARM kernel/VM marker, exact maps and cleared
groups. Recursive read-only mounts, writable evidence/tmpfs boundary, minimal
devices, proc mount and service IPC seccomp barrier are unchanged. After mounting,
this purpose retains FSETID in addition to the original capability mask to
preserve the signed `02755` modes. Default callers retain mask `0x400cb`; the
explicit numeric fixture uses `0x400db`. These capabilities exist only in the
mapped guest user namespace. Host/container capabilities and P0 are unchanged.

The private installer Runner resource facade changes only its exact held
`RLIMIT_NOFILE=(128,128)` request to `(8192,8192)`, refusing a smaller inherited
hard limit or a changed original request. Other limits and the shared runtime
remain unchanged. Both ordinary-parent and engine launches use this binding.
The disposable guest unit sets `LimitNOFILE=8192`; root readback checks that its
inherited soft and hard budgets suffice. This covers the observer's bounded4096
retained hardlink groups without silently returning an incomplete scan.

The signed dbus helper mode is `04110`. Ordinary UID23001 cannot independently
read that exported file. The ordinary parent therefore exports a provisional
result after its existing inventory/source checks and engine-group retirement.
It publishes no final installed lock. After the entire ordinary-parent process
group retires, the root VM service uses the existing bounded full-root observer
to read every exported node, including that file, without changing its mode.
It passes raw outside ownership to the real database reader, then normalizes
only the exact closed ID map for comparison with the signed payload. It checks
all hashes, modes, numeric ownership, closed hardlinks, database records,
per-package ownership, preservation fixtures, parent inventory and source/cache.
Unmapped IDs refuse. Only this independent readback promotes the final lock and
atomically replaces the provisional result; publication failures revoke newly
created outputs. Namespace FD/lease cleanup must also pass before the UART exit
can succeed. Host protocol validation requires all new readback proof flags.

Source and inert controls do not establish actual VM support, a completed587
transaction, target boot/session, Asahi installation, M2/16K hardware acceptance,
performance, production trust custody or recovery. The failed run38876211907
stopped during payload profiling before the VM. Its first offending member was
not retained; the passive six-header audit establishes a necessary correction,
not first-path attribution. A new owned VM execution remains required.

A subsequent actual x86_64 host component fixture passed using subordinate IDs,
the same proposed core/bootstrap/FD transfer bytes, synthetic file contents with
the exact six metadata records, and1048 closed two-link groups. It exercised the
real isolation barrier and capability reduction; both supervised children had
8192 descriptors. The ordinary parent received EACCES for04110 and independent
readback preserved its metadata. All private processes/mounts/files were retired.
The harness substituted host classification for the ARM/VM-only guards; no
kernel syscall was mocked. This establishes host kernel components only. The
pinned ARM VM and587-package transaction remain unrun for this successor.
