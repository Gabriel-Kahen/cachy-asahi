#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same readonly tool closure, emitting a distinct UI-seat operation profile."""
import importlib.util,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
 if not (__debug__ and sys.flags.isolated):raise RuntimeError('isolated Python and assertions required')
 C=load('ui_seat_contract',HERE/'contract.py');C.verify()
 G=load('ui_frozen_guard',HERE/'frozen/rtc/host_guard.py');original=G.load
 G.load=lambda name:C if name=='contract' else original(name)
 G.main()
if __name__=='__main__':main()
