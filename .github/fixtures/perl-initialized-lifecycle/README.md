# Public initialized Perl lifecycle CI operands

These are exact public r74 DATA bodies from the retained
`Root-warm-perl-ssh-empty-proof-trial-r1` observation, copied through the
fullscan preparation's `operation/proof` directory. They contain public
metadata and natural retirement evidence. They confer no Root authority,
qualification, VM, native, M2, release or preservation acceptance.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| empty-proof.DATA.json | 3757 | 7a84225e2bbf3ed91fe6eb62d9d974399b01bbe30b2a82da19b94294388d253a |
| empty-closure.DATA.json | 7556 | 135759471cc66dbcafcc0b14600a0c5fc1badcc2e1fc6e458199eb0269f731dc |

The dedicated lifecycle runner verifies both whole bodies before testing.
These are complete original files, not reconstructed MODEL certificates.
The Source65 modules come from the checked-out, whole-sealed public family;
the frozen initialized qualification family comes from published ancestor
`ead107b0f904d72e61b262f77444e46abd80cd7f`, with its original
2188-byte lock SHA256 `f51c3110877cc9f8d4056c064a43c339af4f6d026b9f7055d5a1ea749ad7e55a`.
The constructor authenticates both complete dependency seals.

Run `python3 -I -B -Werror::ResourceWarning .github/scripts/perl_initialized_lifecycle_ci.py`
from a checkout containing that published ancestor, with Bash, coreutils,
findutils and attr installed. The runner changes only the sealed tests' local
operand path assignments in memory; all source and test files stay byte/mode
identical. It runs nine genuine Source/MODEL controls, eight ordinary temporary
filesystem shell controls and seven exact public closure/decoder controls,
requiring all 24 to pass without skips.
