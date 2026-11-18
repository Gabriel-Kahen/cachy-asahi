# SPDX-License-Identifier: MIT
"""Passive plan join and finite hooks for the existing Overlay583 owner."""

import argparse
import importlib.util
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent


def load(path):
    spec=importlib.util.spec_from_file_location("fish_upgrade_"+path.stem,path)
    loaded=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def worker(T, root, supplement):
    for name in ("operands.py","probe.py","bridge.py"):
        T.read(root/name,supplement["files"][name],cap=128*1024,collect=False)
    path=root/"guest.py"
    raw=T.read(path,supplement["files"]["guest.py"],cap=128*1024)
    spec=importlib.util.spec_from_file_location("fish_upgrade_guest",path)
    guest=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),"exec"),guest.__dict__)
    return guest


def selected_plan(T, O, G, packet, nonce, supplement):
    T.need(re.fullmatch("[a-f0-9]{32}",nonce)
           and packet["target"]==O.TARGET
           and packet["files"][O.REPO+"/"+O.PREVIOUS]==O.PIN_OLD
           and packet["files"][O.REPO+"/"+O.PREVIOUS+".sig"]==O.PIN_OLD_SIG
           and packet["signers"][0]==G.OVERLAY_SIGNER
           and supplement["rehearsal"]["fingerprint"] not in packet["signers"],
           "Exact ordinary signed Fish rollback operands and a distinct TEST signer required")
    before,updated=O.inventories(T,T.target_bytes(packet))
    T.need(supplement["inventories"]["before"]==supplement["inventories"]["restored"]==T.pin(before)
           and supplement["inventories"]["upgraded"]==T.pin(updated),
           "Exact private version-only Fish transition required")
    return dict(T.guest_plan(packet,nonce),kind=G.PLAN_KIND,fish_upgrade=supplement)


def passive_plan(T, *, staging, preflight, supplement, supplement_sha256, nonce):
    O=load(HERE/"operands.py")
    selected=O.check_stage(T,supplement,supplement_sha256,sources=HERE)
    G=worker(T,HERE,selected)
    packet=T.choose(staging,selected_lock=T.PINS)
    raw=T.read(preflight,packet["authenticated_preflight"],cap=128*1024)
    plan=selected_plan(T,O,G,T.admit(packet,raw,T.pin(raw)),nonce,selected)
    return dict(mode="FISH_UPGRADE_PLAN_DATA_ONLY",plan=T.pin(T.encoded(plan)),guest_plan=plan,
                host_authority=None,actor="NOT RUN")


def cli():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("staging","preflight","supplement"):
        parser.add_argument("--"+name,type=Path,required=True)
    for name in ("supplement-sha256","nonce"):
        parser.add_argument("--"+name,required=True)
    T=load(HERE.parents[1]/"install/overlay583_trial/trial.py")
    sys.addaudithook(lambda event,_: T.need(not event.startswith(("subprocess.","socket.","ctypes.")),
                                           "No actor is permitted during the passive Fish plan join"))
    print(T.encoded(passive_plan(T,**vars(parser.parse_args()))).decode(),end="")


if __name__=="__main__":
    cli()
