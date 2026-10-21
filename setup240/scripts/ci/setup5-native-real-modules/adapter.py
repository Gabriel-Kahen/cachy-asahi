# SPDX-License-Identifier: MIT
"""Narrow retained-pair adapter of accepted native Tools ownership/run machinery."""
from pathlib import Path
import contract as C


def replace(raw,before,after,count=1):
    C.need(raw.count(before)==count,'fixed inherited adapter anchor differs: '+before[:72]);return raw.replace(before,after)


def source(root):
    raw=(root/'scripts/ci/tools-native/run.py').read_text()
    first='        products={}\n';last="        container='cachy-asahi-product-lifecycle-'";C.need(raw.count(first)==raw.count(last)==1,'one retained stage block required')
    start,end=raw.index(first),raw.index(last);raw=raw[:start]+"        context,products=C.stage_inputs(source,out,base,checks,bind)\n        report['products']={n:dict(version=p['version'],sha256=p['sha256'],accepted_pair=p['accepted_pair'],origin='ROOT_ACCEPTED_NATIVE_PAIR_REUSED_NOT_REBUILT') for n,p in products.items()}\n"+raw[end:]
    for before,after,count in (
        ('len(self)<8','len(self)<4',1),('THREE_UNSELECTED_TOOLS_CANDIDATES','SETUP5_LEGACY_AND_INSTALLED_REAL_MODULES_581',1),
        ('--env=CACHY_ASAHI_TOOLS_LIFECYCLE=1','--env=CACHY_ASAHI_SETUP5_REAL_LIFECYCLE=1',1),
        ("            '--mount',f'type=bind,src={source}/scripts/ci/zsh-highlighting-native,dst=/highlighting-fixture,readonly',\n", "            '--mount',f'type=bind,src={source},dst=/code,readonly',\n            '--mount',f'type=bind,src={source}/scripts/ci/setup5-native,dst=/legacy,readonly',\n",1),
        ('signal.ITIMER_REAL,2350','signal.ITIMER_REAL,1500',1),
        ("        report.update(lifecycle=life,dependencies=dependencies,status='PASS_NATIVE_TOOLS_PAIRS_AND_CLI_PTY_LIFECYCLE')", "        C.need(C.borrowed_snapshot()==C.BORROWED,'borrowed input packet changed')\n        report.update(lifecycle=life,dependencies=dependencies,borrowed_inputs_preserved=True,status='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES')",1),
        ("if __name__=='__main__':","def main():",1)):
        raw=replace(raw,before,after,count)
    return raw


def namespace(root):
    value=dict(__file__=str(C.HERE/'run.py'),__name__='accepted_retained_setup5_native');exec(compile(source(root),value['__file__'],'exec'),value);value['C']=C;return value
