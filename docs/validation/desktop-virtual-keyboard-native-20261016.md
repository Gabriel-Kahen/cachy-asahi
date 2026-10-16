# Virtual keyboard native trial

[Actual38894721820](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38894721820) fails before sending any keys. Source/workflow is `641bc3a267e95404d650b6bb6331fb8257488632`, workflow SHA256 `46820051d3d57d034b3495055161a7bd6e2cb081c5068c09fa8f0b41b43417e8`, source manifest `dbef4bc182f9982bbf9855a1e38307f533882b38da8a4898e243446db41f7664`.

The generic ARM VM boots kernel7.2.10-1-aarch64-ARCH with4096-byte pages. Its real systemd user manager/bus, render-device access and software GBM probe pass. The intended QEMU Virtio Keyboard passes the kernel/device join. Hyprland reports that exact keyboard with US layout and Caps Lock off, plus a separate `gpio-keys` device. The one-keyboard assertion rejects the second device: `Hyprland sole US virtual keyboard differs`. The explicit power-button-device correction is in development; no arbitrary additional keyboard is accepted.

No shortcut, typed shell command, Vim edit, input delivery or frame passes in this actual. Managed units stop and their runtime directory disappears. All14 runtime cleanup records pass; owned base image/probe absence is verified. This does not establish physical Apple input, acceleration or hardware behavior.

Root downloads logs and the closed public artifact once. Logs are140304 bytes, SHA256 `03a1413c300bea11c0ca9b3f809fbbf7ab214b8da08b05bbb679a3360b40acd6`. Artifact12042844512 is113285 compressed bytes, SHA256 `278236e8e36f225df68afc6e57dc6ac15f665c60378afce8ac3ca284d2b770e3`; all40 declared files/350788 raw bytes join their retention hashes and sizes. Raw disks, homes and package caches are not exported.
