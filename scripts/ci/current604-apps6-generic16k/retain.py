# SPDX-License-Identifier: MIT
"""Original full604/kernel/caps/raw-event guards, exactly12 selected first frames."""
import contract as C

def derive(text):
 text=C.one(text,"raw['workflow_scope']=='installed604-welcome4-management-generic16k'","raw['workflow_scope']=='independent-installed-apps6-current604-management-generic16k-profile' and raw.get('profile')==selected")
 text=C.one(text,"len(raw['frames'])==24","len(raw['frames'])==12")
 text=C.one(text,"'exact24 real frames required'","'exact12 selected real frames required'")
 return C.one(text,"'RETAINED_ACTUAL604_GUI_METADATA_PIXELS_PENDING_REVIEW'","'RETAINED_SINGLE_PROFILE_APPS6_ACTUAL604_GENERIC16K_PIXELS_PENDING_REVIEW'")

def retain(output,producer,runtime,runner,kernel,source):
 owner=C.json_read(output/'result.json',16*1024**2);selected=C.profile(owner.get('profile'))
 module=C.module('_profile604_retention',C.OLD+'/retain.py',{'contract':C},derive)
 module.selected=selected;module.FRAMES=tuple(selected+'-'+v for v in module.VIEWS)
 return module.retain(output,producer,runtime,runner,kernel,source)
