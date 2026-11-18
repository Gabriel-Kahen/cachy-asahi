# Current606 R8 minimal desktop rehearsal on emulated AArch64 with 16 KiB pages

November 18, 2026. **HOLD.** The minimal case booted an emulated AArch64 guest
with 16,384-byte pages from source `2dfa9584bac29ccd754e20c213fbf5e4417f99f1`.
The guest inventory joined the exact 606-package lock with SHA-256
`9674da5a122395df4c496e7af4ed68dfb091d0793e184eff7d317bbb4df1dcf9`.
[Run 44363370140, attempt 1](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44363370140)

The PCI virtio keyboard bound to `virtio_input` in the guest. Key injection
was untested. The **View report** control that stopped R4 received focus at
sequence 15 and opened the package-manager lock refusal report at sequence 16.
Root visually reviewed all 11 retained original frames and confirmed that the
lock-refusal report was expanded. Independent replay verified the bytes of
those 11 frames. The planned sequence required 15.
[Earlier R4 hold](current606-minimal-emulated-arm16k-r4-20261118.md)

The network fixture then failed when it tried to read `/proc/net/if_inet6`.
The guest kernel configuration left IPv6 unset. The session stopped before
the full post-session installed 606-package verifier. All 15 ordered runtime
cleanup records were independently verified before the original build producer
retired.

Independent terminal HOLD SHA-256
`157a16b6f62991390dbd554ad81f4b9b95598cc78119f9f2b75ee76adad877d3`.
The minimal case remains unaccepted. The overlay case and physical M2
validation remain unrun.
