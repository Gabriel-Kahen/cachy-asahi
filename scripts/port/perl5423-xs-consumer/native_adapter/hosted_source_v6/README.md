# XS v6 fixed-root ALPM descriptor Source

The closed v5 Sourceac06bdbe5093e73fe7c67ad75cd830255f897c3b/run43733645464/job132871372912 failed in actor line327: `c.read(desc)` reached the unchanged global ordinary-path guard. The exact rejected operand was not logged. Signed349 inventory contains21 legitimate epoch versions, including avahi1:0.9rc5-1, fakeroot1:1.37.2-3 and fontconfig2:2.18.3-2. Colon filenames explain a reproducible rejected class; the actual failing filename remains an inference. `observed-failure.json` pins the retained DATA and separates those facts. No XS completion is claimed.

V6 adds `alpm_inventory` and `read_alpm_desc` inside the explicitly revised native adapter. The first requires the exact canonical pinned349 inventory and builds exact directory→name/version pairs. The second accepts only `/var/lib/pacman/local/<one admitted name-version>/desc`, including an admitted numeric epoch. It never calls or relaxes global `c.path`; Docker delimiter restrictions and all other callers remain unchanged.

The reader holds Root`/` and every ancestry directory FD, uses read-only/CLOEXEC/NOFOLLOW directory and leaf opens, rejects symlink ancestry/leaf and hardlinks/special files, bounds descriptor bytes to1MiB, checks stable directory links and file FD/path identities before/after reading, rejects binary NUL and requires one exact NAME/VERSION field matching the admitted directory. Wrong roots, traversal, unknown package/version and mutable inputs refuse. It returns only the admitted package/version text. The existing actual inventory hash/equality check remains in the actor. No extra process is launched.

The actor is explicitly NOT byte-identical: only the enumerated inventory-read text block changes. All other old native functions are exact except `actor_dispatch`'s finite primary-error diagnostic seam. Constructor controls prove both inverses. Image seal/preparation, runtime/probes/runner/ABI, caps, work volume NoCopy/order/preentry receipt, deadlines/resources, stdout and successful JSON remain unchanged. Exactly12 of13 consumer files remain unchanged; old native/entry/workflow/provenance/map bodies are archived under previous-v5. V6 outer operation/ref/alias delegates consumer-v1 and image-seal-v4 explicitly. The retained receipt stays work-preentry-v5.json; no protocol rename or extra output namespace is introduced.

If the actor fails before output exists and receipt recording also fails, its original exception is raised as primary with a bounded secondary note, suppressing the misleading reversed cause chain. No empty output or success receipt is fabricated. A receipt error after actor success still fails. Existing failure/cleanup and uncertain-outcome rules remain active.

Twenty-two fenced controls pass: nine full actual316-parent/321 inverse/typed-payload/changed-actor guards; thirteen real owned DirFD fixture and diagnostic controls, including all three actual epoch examples, normal package, wrong roots/traversal/inventory, symlink ancestry/leaf, hardlink/FIFO/size, mutations/replacements, unchanged global path guard and primary/secondary error combinations. Tests invoke extracted changed DATA callables and private ordinary fixtures only; no Source actor role, Docker, compiler, GPG, network, canonical lease, Reader or publication runs. A model pass is not new native/XS acceptance.

```sh
python3.14 -I -B -Werror::ResourceWarning test_source.py --previous-xs-source "$EXACT_CLOSED_SOURCE316"
python3.14 -I -B -Werror::ResourceWarning test_alpm.py --inventory "$EXACT_CLOSED_SOURCE316/accepted/packages.txt"
```

The constructor performs DATA render/inverse only in controls. No Source export or new actual role has run. Root-only future construction, after separate admission and independent whole profile review:

```sh
python3 -I -B prepare.py --previous-xs-source "$EXACT_CLOSED_SOURCE316" \
  --profile-sha256 "$REVIEWED_V6_PROFILE_SHA256" --output "$FRESH_DISJOINT_SOURCE_OUTPUT"
```

The proposed Source has321 files; `validation.json` retains exact in-memory render bytes/map/tree and profile pin. Source/ref/run/job/Original/authority/approval/Reader/image selectors remain NULL. Root must separately issue any export/publication/readback, new once case and matching independent Reader update. All old Sources/roles/failures remain unchanged and closed. New native XS, installation, native16K, M2, performance and release remain NOT RUN/unqualified.
