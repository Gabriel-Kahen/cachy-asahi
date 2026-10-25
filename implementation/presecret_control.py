#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One fixed original Apps16 source suite with whole verified workspace input94."""
import argparse,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE))
import source_guard as G
OLD="D.parent/'apps16-inputs/recipe-source/packages/tools/cachy-asahi-apps16/inventory.py'"
NEW="_EXACT_APPS16_INPUTS/'recipe-source/packages/tools/cachy-asahi-apps16/inventory.py'"
def main():
 p=argparse.ArgumentParser();p.add_argument('--control',choices=('apps16-common',),required=True);p.add_argument('--apps16-inputs',type=Path,required=True);a=p.parse_args();G.verify(require_known=True);carrier=a.apps16_inputs;G.need(carrier.is_absolute()and carrier==carrier.resolve()and not any(q.is_symlink()for q in(carrier,*carrier.parents)),'canonical explicit Apps16 workspace input')
 home=ROOT/'parent574';s=importlib.util.spec_from_file_location('_exact_original_apps16_input_policy',home/'apps16_common.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C);selection=G.obj(home/'apps16-selection.json')['selection'];G.need(len(selection['files'])==94 and selection['source']=='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11','exact original whole94 carrier selection');C.closed(carrier,selection['files']);index=C.obj(carrier/'index.json');C.need(C.pin(C.read(carrier/'index.json'))==selection['index'],'whole exact input index');decision=C.obj(carrier/C.member(index['acceptance']));C.need(C.pin(C.read(carrier/index['acceptance']))==selection['acceptance'],'original Root input custody');C.index_check(index,selection['files'],G.obj(home/'apps16-recipe-map.json'),decision)
 raw=G.read(home/'apps16_common.py');text=raw.decode();G.need(text.count(OLD)==1,'one exact original workspace-relative control input operand');text=text.replace(OLD,NEW,1);G.need(text.count(NEW)==1 and text.replace(NEW,OLD,1).encode()==raw,'entire original control byte inverse');scope=dict(__name__='__main__',__file__=str(home/'apps16_common.py'),_EXACT_APPS16_INPUTS=carrier);sys.argv=[scope['__file__']];exec(compile(text,scope['__file__'],'exec'),scope)
if __name__=='__main__':main()
