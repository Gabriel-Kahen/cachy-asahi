# SPDX-License-Identifier: MIT
"""At most seven fixed post-session markers. DATA only, never GUI acceptance."""
STAGES=('management_restore_begin','management_restore_end','installed606_verify_begin','installed606_verify_end','manager_cleanup_begin','manager_cleanup_end','complete_boundary')
_last=-1

def mark(emit,stage):
 global _last
 if type(stage)is not str or stage not in STAGES:return False
 ordinal=STAGES.index(stage)
 if ordinal<=_last:return False
 _last=ordinal
 try:emit('post_session_stage_DATA',schema=1,stage=stage,ordinal=ordinal+1,status='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE')
 except Exception:return False
 return True
