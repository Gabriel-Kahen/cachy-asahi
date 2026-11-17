# Unissued baseline public-cache body observer

This new passive family derives the maintained r2 read-only controller for one
known prepared backing:1610612736B/49da69b9262e089e08aa84063ed14ca13e66189f9c1e396616ab5f5cb5e24b81.
It changes neither the original recovery proposal nor its bd72 chain correction.
Root90's seven-command success is pinned provenance, not authority for this new
operation. No actor, raw-body read, lease, profile, nonce or Root grant is entered.

The only operation commands, each debugfs without -w on /prepared/guest.raw, are:

1. stat /etc/ld.so.cache
2. stat /etc
3. dump /etc/ld.so.cache /output/cache.bin
4. stat /etc/ld.so.cache
5. stat /etc

No overlay input, qemu-img, conversion, QEMU guest, mount, fsck, other pathname,
private child traversal, key or raw output is present. Expected cache body is
17551B/SHA2560128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215.
Both named metadata observations must repeat exactly and match the existing
public baseline. Body bytes must match the exact known pin. No cache semantics
or provider transition is evaluated; another family owns that analysis.

derive.py authenticates four exact r2 source preimages and returns only scoped
binding/resource/artifact changes. One RO backing replaces overlay+backing;
code, request and limiter remain RO; one fresh small output is RW (five binds).
The actor FSIZE and aggregate cache/artifact cap are4MiB. Each stat stream is
at most16KiB and dump FSIZE at most1MiB; exactly ten command log/retirement files,
cache.bin and a bounded summary are retained. There is no observation.raw.

The actor/controller512MiB,1CPU,64PID,swap0 ceilings remain. The existing
controller32MiB transport/receipt budget is separate from the4MiB public artifact
budget and remains unchanged to preserve its command supervision function.
Actor AS4GiB,180s shared phase,10s command ceilings,90s cleanup,480s outer and
485s external supervision remain. Initial RAM3GiB/disk10GiB with live2GiB reserves
remain conservative. No budget or deadline is extended.

Critical proof, real independent NB conflict, same FD/PIDFD/start/identity,
atomic GO, live cgroup, periodic reserve, natural process retirement, owned
census/cleanup and CLOSE_ONLY functions are AST-identical to r2. Limiter function
bodies remain identical; only the declared FSIZE constant narrows. Source/body
preimages plus complete r2 inverse in the external preparation make review and
replay concrete. All Root parameters, runtime/profile, authority, nonce, times
and output remain NULL. Root must review/select fresh resources and current
custody and then issue/enter the concrete external packet.

Run test_baseline.py with Python -I -B. The11 actor/syscall/socket/lease-fenced
controls check the five literal commands; NULL refusals; backing/tool/resource/
overlay drift; strict named metadata and repeat failures; unknown body refusal;
no private parser scope; exact four-file derivative/inverse and core equality;
single-input mounts/4MiB FSIZE; small manifest/cap/acceptance refusals; and
retirement-before-success ordering. Positive extraction of the actual body is
NOT RUN and cannot be supplied by a synthetic fixture.

Root's actual extraction, independent cleanup and body custody remain required.
No lifecycle, cache transition, VM, native/M2 or release acceptance is granted.
