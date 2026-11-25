# Virtual desktop completion successor

The generic desktop guest boot parent emits `desktop_session_exit` after the
user session exits zero and the owned seatd group is reaped and verified absent.
The event includes the proof nonce and the observed session and seatd exit
codes. The runner requires that the event follow both desktop phases and be the
last protocol event in its UART read. After QMP shutdown, the runner checks
bounded UART EOF and rejects further events and partial markers. The private
controller replays the serial log and checks its byte count and digest before
projecting `desktop_completion` schema 2. The composed caller requires that
receipt and its terminal event before publishing frame evidence.

Select a new source revision and authorize its exact virtual source map before
using this route. The candidate changes the guest, runner, controller and
composed reader. Existing packet locks and retained runs use their original
source revisions. The successor receipt applies to captures made by this
candidate. [Frozen caller source gate](../../scripts/ci/development/virtual_stage.py)

Run the portable source controls from a checkout of the candidate revision.

```sh
python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/virtual -p 'test_*.py'
python3 -B -Werror::ResourceWarning scripts/ci/development/test_virtual_stage.py
```

The focused tests use local socket pairs and modeled guest cleanup. They
exercise same-read and next-read failures, duplicate and partial events, missing
EOF, and mismatched completion receipts. A newly admitted generic QEMU desktop
run and independent frame review are required for execution evidence. Both
physical M2 Air records are `NOT RUN`.
