# Generic16K mapped shell tools

[Actual38921035059](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38921035059), source/workflow `a37312e35dc69c539eaac3648c312c056c4aad36`, fetches the original pinned Asahi kernel archive through the bounded direct-tag transport, verifies all262965559bytes/SHA256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`, and compiles the separate diagnostic PTY kernel. The earlier38918311247 HTTP429 failure remains unchanged.

The guest actually boots aarch64 kernel7.1.13-generic16k-smoke with16384-byte pages and passes mmap/mprotect/file-offset smoke checks. Exact source-mapped tool payload capture, interpreter/dependency ELF alignment and the static probe succeed. These payloads are unpacked and not package-manager installations.

The guest then fails its first Fish driver: `eventfd: Function not implemented`. The actual kernel configuration has `# CONFIG_EVENTFD is not set`. Root independently joins the retained UART tail hash and these boot/probe/failure markers. A source-derived diagnostic kernel correction is pending; no case or process/ownership/preservation gate is waived. The remaining Fish/Zsh/mirror runtime assertions are not accepted by this failed trial.

QEMU exits naturally0 after36.525379seconds with its process group absent, but the guest marker remains FAIL. Capture-container absence/private cleanup and borrowed-producer preservation are recorded; the failed runtime's producer/finalization field remains PENDING and does not confer ordered-cleanup acceptance. No GUI, M2, performance or release credit follows.

The once-collected original artifact12054652599 is130200bytes, SHA256 `0bf8ae623e749e6d4a865c765c9ee8ea07f1ec8d4515f2827ab79578f163a119`; log ZIP94074bytes, SHA256 `20217082b41b1e038b87306a40f54913ee7e71c684b8673e4a9013217b193400`. Its bounded runtime record and original source/kernel configuration remain unchanged.
