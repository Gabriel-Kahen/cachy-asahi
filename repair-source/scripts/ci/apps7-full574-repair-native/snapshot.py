#!/usr/bin/python3 -I
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('original_snapshot',Path('/source/scripts/ci/apps-full574-native/snapshot.py'));H.C=C
if __name__=='__main__':H.main()
