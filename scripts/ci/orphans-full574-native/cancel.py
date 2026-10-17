#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Native operator-cancel fixture; same selected API and copied-root guards."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def main():
 C.source(Path('/source'));p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--request-sha256',required=True);a=p.parse_args()
 selected=C.load('selected_cancel',Path('/source/scripts/orphans/selected.py'));args=selected.request(a.request,a.request_sha256);value=selected.apply(args,cancel=lambda:True)
 C.need(value['status']=='CANCELLED_NOT_APPLIED' and value['transaction']=='NOT_STARTED','operator cancel must not start transaction');print(C.encoded(value).decode(),end='')
if __name__=='__main__':main()
