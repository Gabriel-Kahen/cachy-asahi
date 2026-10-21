#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete closed source, bounded source fixtures and NULL/refusal controls."""
import importlib.util,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE/'implementation'))
import latest_guard as G

def main():
 result=G.verify()
 for path in sorted((HERE/'implementation').rglob('*.py')):compile(path.read_bytes(),str(path),'exec')
 p=subprocess.run([sys.executable,'-I','-B','-m','unittest','discover','-s',str(HERE/'tests'),'-p','test_*.py','-v'],capture_output=True,timeout=120)
 sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr)
 if p.returncode or b'skipped='in p.stderr or b' (skipped='in p.stderr:raise ValueError('complete source/refusal controls failed or skipped')
 print(json.dumps(dict(status='PASS_COMPLETE_SOURCE_ONLY_NO_NATIVE_CREDIT',source=result,tests='NO_SKIPS'),sort_keys=True))
if __name__=='__main__':main()
