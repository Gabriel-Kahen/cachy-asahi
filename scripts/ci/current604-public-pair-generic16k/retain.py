# SPDX-License-Identifier: MIT
"""Original full604/kernel/caps/raw-event guards, exactly12 selected first frames."""
import contract as C
context604=C.module('_profile604_qemu_context',C.NEW+'/context604.py')

def derive(text):
 text=C.one(text,'import contract as C','import contract as C\nimport context604')
 text=C.one(text,"copy(runtime/name,'runtime/'+name,cap,required=name in ('runtime.json','events.log','elf16k.json'))","copy(runtime/('installed604-capture.json' if name=='fixture/installed604-capture.json' else name),'runtime/'+name,cap,required=name in ('runtime.json','events.log','elf16k.json','fixture/installed604-capture.json'))")
 text=C.one(text,"capture=C.json_read(runtime/'fixture/installed604-capture.json',65536)","capture=C.json_read(runtime/'installed604-capture.json',65536)")
 text=C.one(text,"('runtime-image.log',16*1024**2)","('runtime-image.log',16*1024**2),('qemu-tooling-image.log',16*1024**2)")
 text=C.one(text,"raw=C.json_read(runtime/'runtime.json',16*1024**2);lock=C.json_read(runner/'candidate-lock.json')","raw=C.json_read(runtime/'runtime.json',16*1024**2);lock=C.json_read(runner/'candidate-lock.json')\n        C.need(len(raw.get('cleanup',[]))==15 and all(r.get('exit',0)==0 for r in raw['cleanup']) and context604.launcher_retired(raw,C.ROOT),'all original roles plus exact owned QEMU image retirement required')")
 text=C.one(text,"raw['workflow_scope']=='installed604-welcome4-management-generic16k'","raw['workflow_scope']=='independent-installed-public-pairs-apps6-current604-management-generic16k-profile' and raw.get('profile')==selected")
 text=C.one(text,"len(raw['frames'])==24","len(raw['frames'])==12")
 text=C.one(text,"'exact24 real frames required'","'exact12 selected real frames required'")
 return C.one(text,"'RETAINED_ACTUAL604_GUI_METADATA_PIXELS_PENDING_REVIEW'","'RETAINED_SINGLE_PROFILE_PUBLIC_PAIRS_APPS6_ACTUAL604_GENERIC16K_PIXELS_PENDING_REVIEW'")

def retain(output,producer,runtime,runner,kernel,source):
 owner=C.json_read(output/'result.json',16*1024**2);selected=C.profile(owner.get('profile'))
 module=C.module('_profile604_retention',C.OLD+'/retain.py',{'contract':C,'context604':context604},derive)
 module.selected=selected;module.FRAMES=tuple(selected+'-'+v for v in module.VIEWS)
 public=module.retain(output,producer,runtime,runner,kernel,source)
 assets=output/'fresh-public-gui-assets';receipt=C.json_read(assets/'provenance.json')
 C.need(receipt==owner['public_gui_assets'],'actual returned fresh asset binding/provenance differs')
 C.AS.asset_directory(assets,receipt['binding'],source)
 ledger=C.json_read(public/'retention.json')
 paths=[assets/'index.json',assets/'provenance.json',*(assets/'assets').iterdir()]
 C.need(len(paths)==11,'closed actual fresh GUI asset evidence')
 for path in paths:
  name='fresh-public-gui-assets/'+path.relative_to(assets).as_posix();raw=C.read(path,8*1024**2)
  target=public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  C.need(name not in ledger['files'],'fresh asset retention collision');ledger['files'][name]=dict(bytes=len(raw),sha256=C.sha(raw))
 ledger['bytes']=sum(r['bytes'] for r in ledger['files'].values());C.need(ledger['bytes']<=128*1024**2,'original total public cap includes fresh assets')
 C.save(public/'retention.json',ledger);return public
