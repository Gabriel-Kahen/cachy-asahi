#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Native operator-cancel fixture; same selected API and copied-root guards."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def main():
 C.source(Path('/source'));p=argparse.ArgumentParser();p.add_argument('--staged-source',type=Path,required=True);p.add_argument('--request',type=Path,required=True);p.add_argument('--request-sha256',required=True);a=p.parse_args()
 stage=C.load('cancel_rules_stage',C.HERE/'stage_source.py');stage.validate(C,a.staged_source)
 selected=C.load('selected_cancel',a.staged_source/'scripts/orphans/selected.py')
 C.load('held_cancel_payloads',C.HERE/'held_payloads.py').configure(selected.T,C,a.staged_source)
 args=selected.request(a.request,a.request_sha256);value=selected.apply(args,cancel=lambda:True)
 C.need(value['status']=='CANCELLED_NOT_APPLIED' and value['transaction']=='NOT_STARTED','operator cancel must not start transaction');print(C.encoded(value).decode(),end='')
if __name__=='__main__':main()
