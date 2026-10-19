"""Typed finite boot scope, never mapping/integrity/lifecycle qualification."""
import re
import inputs
P,_,_,_=inputs.broker()
BOOT_SCOPE=('GENERIC16K_BOOT','ACTUAL_PID1','AT_PAGESZ_16384','DM_VERSION','VERITY_TARGET_AVAILABLE','NATURAL_POWEROFF')
def boot(value,build):
 P.need(type(value)is dict and set(value)=={'purpose','source','run','kernel_build_decision','scope','page_size','PID1','DM_VERSION','verity_target','poweroff','verity_mapping','integrity','lifecycle'},'finite boot availability descriptor')
 P.need(value['purpose']=='GNU_VERITY_KERNEL_BOOT_AVAILABILITY_ONLY_V1'and re.fullmatch('[a-f0-9]{40}',value['source'])and re.fullmatch('[1-9][0-9]{0,19}',str(value['run']))and value['kernel_build_decision']==build,'genuine same-build boot descriptor')
 P.need(value['scope']==list(BOOT_SCOPE)and value['page_size']==16384 and value['PID1']is True and value['DM_VERSION']is True and value['verity_target']is True and value['poweroff']=='NATURAL'and all(value[k]=='NOT_QUALIFIED'for k in('verity_mapping','integrity','lifecycle')),'boot availability cannot qualify runtime mapping/integrity/lifecycle');return value
