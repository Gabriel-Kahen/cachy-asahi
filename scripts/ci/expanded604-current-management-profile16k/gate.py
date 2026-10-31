#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original full prerequisite gate, with a mandatory single-profile operand."""
import contract as C
import ci

def derive(text):return C.one(text,"('implementation','implementation_revision','workflow_sha','help')","('implementation','implementation_revision','workflow_sha','profile','help')")
_BASE=C.module('_profile604_gate',C.OLD+'/gate.py',{'contract':C,'ci':ci},derive)
main=_BASE.main
if __name__=='__main__':raise SystemExit(main())
