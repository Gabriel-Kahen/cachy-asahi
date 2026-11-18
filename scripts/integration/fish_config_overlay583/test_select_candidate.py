#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Controls for the passive signed Fish development selection."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location(
    "fish_candidate_controls", Path(__file__).with_name("select_candidate.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
T = S.load_trial()


class Controls(unittest.TestCase):
    def setUp(self):
        self.operand = SimpleNamespace(CODE=("guest.py", "operands.py", "probe.py", "bridge.py"))
        self.packet = dict(preflight=T.pin(b"authenticated original baseline"))
        self.stage = dict(qualification=dict(native_pair="PASS", run=1), rehearsal=dict(fingerprint="A" * 40),
                          inventories={phase: T.pin(phase.encode()) for phase in ("before", "upgraded", "restored")},
                          files={name: T.pin(name.encode()) for name in self.operand.CODE},
                          receipt=T.pin(b"exact signed supplement"))
        absent = dict(bind_container_absent=True, run_container_absent=True, scope_absent=True)
        self.terminal = dict(issuer="Root", status=S.TERMINAL, phase=None, guest_platform="aarch64 QEMU TCG",
                             page_size=16384, physical_M2="NOT RUN", native_16KiB_hardware="NOT RUN",
                             evidence_files=22, observations=[absent, absent], native_pair=self.stage["qualification"],
                             test_signer=self.stage["rehearsal"],
                             matched_locks={phase: dict(ref, count=583) for phase, ref in self.stage["inventories"].items()})
        self.selection = dict(kind="ROOT_OVERLAY583_QEMU_TCG_SELECTION_V1", issuer="Root", preflight=self.packet["preflight"],
                              fish_upgrade=self.stage["receipt"], source={
                                  f"scripts/integration/fish_config_overlay583/{name}": pin
                                  for name, pin in self.stage["files"].items()})

    def verify(self, terminal=None, selection=None):
        S.bound_guest(T, self.operand, self.packet, self.stage,
                      self.terminal if terminal is None else terminal,
                      self.selection if selection is None else selection)

    def test_records_select_exact_original_signed_supplement_and_code(self):
        self.verify()
        substituted = dict(self.selection, fish_upgrade=T.pin(b"another signature for the same candidate"))
        with self.assertRaisesRegex(ValueError, "different baseline or signed Fish supplement"):
            self.verify(selection=substituted)
        substituted = copy.deepcopy(self.selection)
        substituted["source"]["scripts/integration/fish_config_overlay583/guest.py"] = T.pin(b"different guest readback")
        with self.assertRaisesRegex(ValueError, "different baseline or signed Fish supplement"):
            self.verify(selection=substituted)

    def test_held_or_mismatched_rehearsal_cannot_qualify_candidate(self):
        with self.assertRaisesRegex(ValueError, "independently closed"):
            self.verify(terminal=dict(self.terminal, status="HOLD"))
        with self.assertRaisesRegex(ValueError, "native source, TEST signer or retirement differs"):
            self.verify(terminal=dict(self.terminal, observations=self.terminal["observations"][:1]))
        substituted = copy.deepcopy(self.terminal)
        substituted["matched_locks"]["restored"] = substituted["matched_locks"]["upgraded"]
        with self.assertRaisesRegex(ValueError, "original guest inventory observation differs"):
            self.verify(terminal=substituted)


if __name__ == "__main__":
    unittest.main()
