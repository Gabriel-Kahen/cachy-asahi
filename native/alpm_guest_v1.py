# SPDX-License-Identifier: MIT
"""Read-only native consumer exports image-stage ALPM originals as DATA only."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import need
from installed_alpm_v1 import export

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--map-sha256',required=True);args=parser.parse_args()
    need(platform.machine()=='aarch64' and os.getuid()==os.geteuid()!=0,'actual non-root native DATA consumer')
    result=export(args.output,args.map_sha256)
    print(json.dumps(dict(status=result['status'],scope='IMAGE_STAGE_TEST_ALPM_DATA_EXPORT; no184 consumer-execution claim')))
