#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Print verified source recipe DATA only; no output preparation or execution."""
import importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
 if not (__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 s=importlib.util.spec_from_file_location('ui_seat_contract',HERE/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
 original=C.data();ref,receipt=C.reference();requested=C.construct(original)
 if C.inverse(requested)!=original:raise ValueError('original byte inverse differs')
 print(json.dumps({'schema_version':1,'status':'READY_SOURCE_ONLY','operation':C.lock()['operation'],'kernel_release':C.lock()['kernel_release'],'requested_config':C.pin_bytes(requested),'rtc_reference':C.spec()['rtc_bundle_pin'],'ui_seat_delta':C.delta(ref,C.overlay(ref,C.changes())),'dependencies':C.dependencies(),'device_plan':C.device_plan(json.loads((HERE/'device-plan.json').read_text())),'compiler_facts':receipt['config_proof']['compiler_facts'],'resource_proposal':C.lock()['build'],'actual_configure':None,'actual_compile':None,'actual_seat_boot':None,'Root_authority':None,'native16K':'NOT RUN','M2':'NOT RUN','release':False},indent=2,sort_keys=True))
if __name__=='__main__':main()
