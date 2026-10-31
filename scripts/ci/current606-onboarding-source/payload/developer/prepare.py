#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce this exact source only; no signing, Docker, network or acceptance."""
import argparse,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import guard as G

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();fact=G.verify();out=a.output.absolute();G.need(not out.exists()and out.parent.is_dir()and not any(p.is_symlink()for p in(out,*out.parents))and not out.is_relative_to(G.ROOT)and not G.ROOT.is_relative_to(out),'fresh disjoint source-only output');shutil.copytree(G.ROOT,out,ignore=shutil.ignore_patterns('.git','__pycache__'));print(G.enc(fact).decode(),end='')
if __name__=='__main__':main()
