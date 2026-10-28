# Virtual image decoder source registration

October 12, 2026. The coordinator rebound `scripts/virtual/controller.py`'s `CORE` map to seven reviewed source files: common, guest, preparation, runner, GBM probe, image decoder probe and image decoder parser. The three stale guest/preparation/runner hashes are replaced with the published decoder implementation; common and GBM remain unchanged. Every controller AST node outside `CORE` is unchanged.

The seven input files were checked against the current committed Git blobs. A cold source copy passes 127 controller, guest and decoder tests with zero skips. The first attempt's missing auxiliary input and sandbox Unix-socket errors remain in the evidence; adding the exact committed input lock and replaying harmless private socket fixtures completes the checks. No Docker, ARM guest, compiler, package installation or image trial ran.

Evidence: `artifacts/reviews/virtual-core-seven-root-registration-20261012/adoption.json`, SHA256 `1c03e769913bfebe60c5d453965d000600ce6918f81639b923b014fe2ae3629e`. This registers source pins only. The composed development packet and workflow still need their own registration before an actual trial. Earlier SVG failure, hardware checks and performance measurements retain their recorded status.
