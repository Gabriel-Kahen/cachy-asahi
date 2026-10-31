#!/usr/bin/python3 -I
"""Explicit native fixture backend over original unchanged transaction bodies."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('held_payload_fixture',C.HERE/'held_payloads.py')
def main():
 root=Path('/source');C.source(root);T=H.configure(C.load('held_original_transaction',root/'scripts/apps/transaction.py'),C,root)
 H.supervisor(T,root/'scripts/apps/transaction.py',[C.HERE/'fixture_backend.py'])
 return T.main()
if __name__=='__main__':raise SystemExit(main())
