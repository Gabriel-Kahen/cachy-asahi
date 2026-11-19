# Current606 minimal desktop rehearsal on emulated ARM with 16 KiB pages

On November 19 UTC, run `44445477874`, job `135296451477`, exercised the
`minimal-generic16k` profile on native AArch64 hosted infrastructure with a
generic emulated ARM guest. The exact controlled source was
`4c92878695ead3f22b53b997a691695ecb629bb0`. The desktop reported AArch64 and
16,384-byte pages under its actual guest kernel.
[Hosted run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44445477874)

- The installed Welcome8 desktop passed the complete GUI contract. The 15
  reviewed frames cover the system and guidance panels, terminal and file
  manager launch, DNS and management reports, unavailable and refused tools,
  cancellation, and a successful retry. Welcome8 still displays the report
  format warning on cancellation. Welcome9 corrects that behavior in its
  separately tested code. [Welcome9 change](https://github.com/Gabriel-Kahen/cachy-asahi/pull/593)
- The strict installed-state check matched all 606 packages, 114,247 filesystem
  entries and 4,918,288,238 payload bytes across the two scans. The host
  verified that the guest runtime retired before cleaning up the package
  producer.
- The retention command reported success with no errors. GitHub emitted its
  two-minute timeout about 20 ms later. The next step packed all 248 evidence
  members and the upload completed. The retained original is 27,519,740 bytes
  with SHA-256 `03d052a3a568e1cf051d15c4be3999b23a890c7778489b631d8eed56326188c2`.

The run's independent disposition is HOLD because the hosted export step
failed its deadline. R16 removes the duplicate whole-source check at the
entry to ARM16K retention. Its remaining proof still runs before export
begins, and both workflow deadlines are unchanged. The matching overlay run,
physical M2 behavior, and release acceptance remain pending.
[R16 source](https://github.com/Gabriel-Kahen/cachy-asahi/tree/229b143302608ca0a726f5618dc404fe11fcde74)
