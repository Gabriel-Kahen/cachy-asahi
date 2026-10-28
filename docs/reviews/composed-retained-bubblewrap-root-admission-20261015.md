# Retained-input composed run: Root admission

Root accepts the authenticated failed readout for [run 38668263227](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38668263227), Source `148f8a98`, Data `2b312bf8`, Code `677d3ba9`. The read-only seal check passes for 191 files, 72 inputs and 549 Git inputs; actual review receipt is `626bc1010ea75d062a26b156845ea0e0236c44b331c297f13d07a81a65f226f8`.

All 501 acquisition objects and 249 input signatures pass authentication. The retained bubblewrap package/signature match their original pinned bytes. Four original development-package pairs reproduce byte-for-byte in separate native ARM containers, and seven initial integration components pass. These are the recorded original versions on a generic 4 KiB ARM runner.

Installer preflight fails at `RECEIVER_ACCEPT / P0_REFUSED`. Its precise private child cause remains unknown because the relevant operands were not exported. Initial owned-image cleanup and handoff/startup cleanup pass separately. Handoff acceptance, restaging and later components remain unrun; phase publication fails. Source also deliberately refuses overall installer publication.

The new three input chunks are supported by mandatory authenticated seed control flow and downstream cache/signature evidence. Raw GitHub Secret value readback is unavailable. No target installation, recovery, M2, 16K compatibility, performance or full-port acceptance follows.

See the detailed actual review at `artifacts/reviews/composed-retained-bubblewrap-run-38668263227-20261014/REVIEW.md`. Root's finite decision is retained at `artifacts/reviews/composed-retained-bubblewrap-root-admission-20261015/admission.json`.
