# Independent KSM154 registration audit

Disposition: **verified finite source registration and inert wiring; native/readiness acceptance is NOT ESTABLISHED.** No implementation, shared packet, RequiredPaths, workflow, Git state or prior evidence was edited by this review. Historical KSM5 remains FAIL; its raw caller exception and actual timeout cause remain UNKNOWN.

## Authenticated registration

The registered packet is `7b6f1519cc901c9e07af326b784b010ebac6a454b841fc099f0ea5e9a873d2e3`. Its 154 source rows total 2,360,916 bytes. Every SHA, size and mode matches both the Root `source154` capture and the current primary path. The capture contains exactly those 154 files plus the separate packet, with no PYC files. Relative paths and row schemas remain closed.

Compared with the historical 152-row packet, the exact union adds `producer_driver.py` and `test_producer_driver.py`, changes only `consumer.py`, `executor.py` and `required_paths.py`, retains 149 rows exactly, and removes none. RequiredPaths is the exact literal 154-entry set, including the new driver pair and excluding packet self-hashing. The whole workflow remains `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`; its packet digest comes from dispatch input, avoiding a literal packet/workflow hash cycle.

The author receipt `3718825905250fd17647c73ae43195105a4c3d6e0466f5ca49a4b29ea43c4c17` and independent custody receipt `efef80fc8e6cbd557f1bda4c9c7073abdf66b8dc916bdf7aacccb6b73d1b137c` authenticate. All 360 author and 329 peer indexed rows authenticate by bytes and mode. Root's 693 checked-record count additionally includes four separate observations of the source pair; it is not a claim of 693 unique artifact paths.

Original preservation is explicit: four original recipes, 71 input pins and all 159 current initial source hashes/modes remain unchanged against the original integration lock `d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`. Of those 159, 82 also occur in this KSM154 capture; the other 77 are outside this finite packet. This capture is not mislabeled as a complete original159 capture.

## Fresh cold bootstrap and caller controls

The actual workflow heredoc was extracted byte-exactly, compiled cold and executed. Actual captured `acceptance.git` and `acceptance.capture` remained unchanged; only stdlib process/selector/read transport and signal APIs supplied synthetic Git responses. The fixture provided 155 blobs including the external packet and answered 158 queries. The actual bootstrap copied and rechecked all 154 source rows before execution stopped at `os.execve`.

This is accepted source data against a synthetic commit/tree fixture. It is not proof of current checkout HEAD, publication, Git object availability or a real Git process result. Actual current-checkout Git proof is a separate Root task.

The copied executor and nine sibling helpers imported cold. Actual source policy, nested held lifecycle BASE/CONTRACT load and private launcher construction passed. Generated Docker/GPG launchers were retained as data and were not executed. The explicit Snapshot importer resolved the driver through its declared stdlib closure, with `_signal` already initialized. Reusing that builtin preserves the trusted startup handler state across the driver's stdlib quarantine.

The actual consumer vector, with the executor's exact `-I/-B/-S` insertions, reached captured `_ksm_native_arm.main` at the actual copied filename with `_Forwarder` installed. A profiling sentinel stopped at its entry, before the original native body ran. Loaded project functions, globals, code or import tokens were not replaced for this path. The inventory selection remains the exact image-bound 11-element command, integer timeout 60 and `log=None`; only that call receives `min(180, producer_end - monotonic())`. Other forwarding and the existing 6600/1650/8460 budgets and 180-second cleanup remain separate preserved constraints.

Wrong packet pin, an unregistered Snapshot source and an expired driver cutoff refused. Import/cache/quarantine state returned to its baseline, the producer output remained absent, and PYC count stayed zero. A fresh replay passed 40 selected driver test methods with zero skips; the one method that sends a real self-SIGINT was explicitly excluded from this inert selection. Four additional controls used the actual private launcher/consumer/driver/importer path: exact original argv and complete private environment were observed before genuine native dispatch, while expired cutoff, wrong cap and wrong output returned 125 without entering native code or creating producer output. This is not a claim of a fresh complete 333-test suite. Exact artifacts are recorded in the final peer receipt.

## Limits and remaining admission

The local inert runtime is Python 3.14.7. The driver directly requires private `Path._raw_paths` and `_str` fields and provides no alternate representation branch. The unchanged workflow selects `ubuntu-24.04-arm` and unpinned `/usr/bin/python3`. Retained runner logs do not establish the exact Python minor or private Path layout. Hosted-runner compatibility must therefore be established before native readiness is claimed; this review does not claim a demonstrated Python3.12 failure or infer the cause of historical KSM5.

The earlier custody seal remains a finite trusted resident-driver protocol, not hostile-interpreter isolation or a complete stdlib execution graph. Source/fixture success does not establish an actual inventory reply, corrected timing, cleanup, native package acceptance, installation, hardware, performance or publication. No actual Git, Docker, native compiler, GPG, kernel namespace, service, network or real-signal actor ran here.

The sealed evidence is `artifacts/reviews/ksm-inventory-driver-root-registration-peer-20261012/receipt.json`. Root must separately verify current committed Git bytes, hosted runtime compatibility and any subsequent native run. No prior KSM5 result is promoted by this registration review.
