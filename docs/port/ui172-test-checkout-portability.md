# UI172 test fixture checkout portability

PR450's static check exposed a test transport bug: `test_construct.py` opened
the historical absolute capture path from `control-inputs.pin.json`. Both its
setup read and its wrong-hash negative control now locate the committed
`control-inputs.json.gz` relative to the test's `HERE`. The original capture
path remains unchanged as provenance; stored and decoded byte/SHA pins still
apply. A new control tests relocation from an unavailable capture path without
changing that reference's size or SHA. `test_materialize.py` already uses only
its checkout-local module and synthetic temporary files; it needed no edit.

Actual validation used two fresh git exports at different temporary checkout
roots, with the patched test overlaid and every exported file's SHA checked
against the current checkout. Python 3.12.13 and 3.14.7 each passed all 24 controls
(12 constructor and 12 materializer), with no skips. A CPython open-audit hook
and wrappers for builtin/io/os opens blocked original private capture roots;
directory-FD paths were resolved through `/proc/self/fd`. Each fence refused
an explicit original-path probe before tests. Test private-path open attempts
were zero. Runner DATA, exported file pins and results are retained in
`manifest_constructor/results/checkout-portability-20261115/`.

Earlier in-place 11+12 control results retain their original scope; they did
not establish checkout portability. Runtime constructor/admission/materializer
code, fixture bytes, historical pins and material DATA are unchanged. No
package rescans, GPG, network, lease, actor or new Root issuance occurred.
