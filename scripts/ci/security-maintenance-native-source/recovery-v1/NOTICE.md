# Sources, licenses and execution status

Factory, native adapter, journal, owned-process code, metadata normalizer,
passive verifier and tests are original project work under MIT; repository
LICENSE applies. No newly acquired external source or dependency is introduced.
The parent Source850 and its retained package inputs, recipes, licenses and
source-delivery notices remain pinned in the exact parent profile. The nine
new modules use Python's standard library; process ownership requires Linux
pidfd, procfs, waitid/WNOWAIT, subreaper and SO_PASSCRED support.

The separate blocking observer is original MIT project code derived from the
retained project observer. It references the existing installed libalpm API and
retained pacman revision `54d94116164b0b2202c6061c4a59c6f3e70820d8`
(GPL-2.0-or-later); contract source and API pins remain explicit. No upstream
source body was newly fetched. It must be compiled and exercised by a future
Root-owned disposable target trial. Architecture declarations, host fixtures,
source inspection and successful Python tests establish no ARM/M2 compatibility.

The development evidence pins the local official libalpm package manfile and
one installed ALPM desc-format observation. These are format evidence, not a
claim that the host database is the target database. Runtime captures exact
target candidate database bytes using the same signed package and fixed config.

No private key or private GPG home is packaged. Future runtime TEST keys are
ephemeral, one-day scoped, validated and retired. No native success, hardware
pass, performance gain, supported overlay or Release admission is claimed.
