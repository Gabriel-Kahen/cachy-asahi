# SPDX-License-Identifier: MIT
"""Original finite recipe/payload/authentication checks with a distinct Apps6 gate."""
from pathlib import Path
import adapter as A
import rules
HERE=Path(__file__).resolve().parent
_original=A.original_contract(A.ROOT)
_original=rules.bind(_original,HERE)
globals().update({k:v for k,v in vars(_original).items() if not k.startswith('_')})
