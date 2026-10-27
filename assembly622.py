# SPDX-License-Identifier: MIT
"""Original full64 authentication and Core signer, selected607 catalog only."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,adapter,desktop622 as X

def module(root):
 core=adapter.core(root);old=C.load('_core622_held_assembly',Path(root)/'scripts/ci/core-native-lifecycle/assemble.py');return X.clone(old,C=core.C)
if __name__=='__main__':module('/core-source').main()
