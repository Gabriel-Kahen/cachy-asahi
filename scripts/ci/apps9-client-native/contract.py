# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A
m=A.module(A.ROOT,'contract.py')
globals().update({k:v for k,v in vars(m).items()if not k.startswith('__')})
if __name__=='__main__':exec(compile(A.text(A.ROOT,'contract.py'),__file__,'exec'),dict(__name__='__main__',__file__=__file__))
