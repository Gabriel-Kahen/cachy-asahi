# SPDX-License-Identifier: MIT
"""Exact six-capability native consumer plus original supervised UID signalling."""
import native_contract as C

def capability_profile(state,ordinary_child=False):
 C.need(state['uid']==state['gid']==0 and all(state[k]==0xdb for k in('CapEff','CapPrm','CapBnd'))and state['CapInh']==state['CapAmb']==0 and state['NoNewPrivs']==1,'unchanged native six-capability root supervisor profile')
 return state
C.capability_profile=capability_profile
