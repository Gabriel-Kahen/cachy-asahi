#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whole accepted581 source controls in its original context, then six-tool controls."""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'latest/implementation'))
import latest_guard as G,next_successor as S

def main():
 fact=G.verify();proof=json.loads((ROOT/'latest/implementation/next-successor.json').read_bytes())
 with S.parent(ROOT,proof)as(old,_):
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(old/'latest/test_source.py')],capture_output=True,timeout=180)
  sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
  if result.returncode:raise ValueError('complete original581 controls failed; no new actors')
 result=subprocess.run([sys.executable,'-I','-B','-Werror','-m','unittest','discover','-s',str(ROOT/'next/tests'),'-p','test_*.py','-v'],capture_output=True,timeout=120)
 sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
 if result.returncode or b'skipped='in result.stderr or b' (skipped='in result.stderr:raise ValueError('six-tool source controls failed or skipped')
 print(json.dumps(dict(status='PASS_SOURCE_ONLY_SIX_TOOL_NO_NEW_NATIVE_CREDIT',source=fact),sort_keys=True))
# BEGIN_VM_TEST3600_WHOLE849_SOURCE_ENTRY
_source849_main=main
def main():
 import validation_capacity as V
 fact=G.verify();p=json.loads((ROOT/'latest/implementation/validation-capacity-parent.json').read_bytes())
 with V.parent(ROOT,p)as(old,_):
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(old/'next/test_source.py')],capture_output=True,timeout=180)
  sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
  if result.returncode:raise ValueError('complete original849 source entry failed; no native actors')
 result=subprocess.run([sys.executable,'-I','-B','-Werror','-m','unittest','discover','-s',str(ROOT/'next/tests'),'-p','test_validation_capacity.py','-v'],capture_output=True,timeout=120)
 sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
 if result.returncode or b'skipped='in result.stderr or b' (skipped='in result.stderr:raise ValueError('VM TEST3600 controls failed or skipped')
 print(json.dumps(dict(status='PASS_SOURCE_ONLY_VM_TEST3600_OUTER_FIT_NOT_ESTABLISHED',source=fact),sort_keys=True))

if __name__=='__main__':main()
