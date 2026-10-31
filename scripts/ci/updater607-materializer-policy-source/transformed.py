# SPDX-License-Identifier: MIT
"""Closed three-stage source DATA edits; never import or execute supplied code."""
import copy,json
CASES=('normal','precommit-exit86','postcommit-exit87')
PARENT='implementation/parent355.json'
MANIFEST='source-manifest.json'
def seal(values,api):
    value=json.loads(values[MANIFEST]);value['files']={n:api.pin(b)for n,b in values.items()if n!=MANIFEST};values[MANIFEST]=api.encoded(value)

def text_edits(values,rows,api,reverse=False):
    for name,edits in rows.items():
        before=values[name];values[name]=api.apply(before,edits,reverse=reverse)
        api.need(api.apply(values[name],edits,reverse=not reverse)==before,'entire readable body inverse '+name)

def descriptor(before,profile,context,edits,api):
    values=dict(before);text_edits(values,edits['descriptor'],api)
    package=json.loads(before['implementation/profile.json'])
    for case in CASES:
        name='cases/'+case+'/scripts/update/aux_copy.py';old=before[name]
        values[name]=api.apply(old,[[context['descriptor_before'],context['descriptor_after']]])
        cfgname='cases/'+case+'/upgrade-config.json';cfg=json.loads(before[cfgname])
        api.need(cfg['code_pins']['scripts/update/aux_copy.py']==api.pin(old)['sha256'],'exact old descriptor code pin')
        cfg['code_pins']['scripts/update/aux_copy.py']=api.pin(values[name])['sha256'];values[cfgname]=api.encoded(cfg)
        row=package['old_source_lineage'][case]['scripts/update/aux_copy.py']
        api.need(row==dict(before=api.pin(old),after=api.pin(old),edits=[],extra=[],whole_inverse=True),'whole original held descriptor lineage')
        row['after']=api.pin(values[name]);row['extra'].append(dict(before=context['descriptor_before'],after=context['descriptor_after']))
        package['cases'][case]['scripts/update/aux_copy.py']=api.pin(values[name]);package['cases'][case]['upgrade-config.json']=api.pin(values[cfgname])
    values['implementation/profile.json']=api.encoded(package)
    binding=copy.deepcopy(context);binding['files']=profile['parent']['files']
    names={n for n in before if before[n]!=values[n]};api.need(len(names)==10,'only ten pre-seal descriptor operands')
    binding['before_bodies']={n:before[n].decode()for n in names}
    parent=json.loads(before[PARENT]);api.need('descriptor_source_binding'not in parent,'fresh descriptor context');parent['descriptor_source_binding']=binding;values[PARENT]=api.encoded(parent);seal(values,api)
    api.need({n:api.pin(b)for n,b in values.items()}==profile['intermediate']['files'],'entire frozen descriptor SOURCE_DATA map, no publication authority')
    return values

def cleanup(before,profile,context,edits,api):
    values=dict(before);text_edits(values,edits['cleanup'],api)
    binding=copy.deepcopy(context);binding['files']=profile['intermediate']['files'];binding['before_bodies']={n:before[n].decode()for n in edits['cleanup']}
    api.need(set(binding['before_bodies'])=={'implementation/runtime.py','implementation/namespace_context.py','test_source.py'},'only cleanup runtime/guard/control operands')
    parent=json.loads(before[PARENT]);api.need('producer_cleanup_binding'not in parent,'fresh cleanup context');parent['producer_cleanup_binding']=binding;values[PARENT]=api.encoded(parent);seal(values,api);return values

def inverse(values,before,intermediate,profile,contexts,edits,api):
    """Restore every public parent byte, with both complete body/map inverses."""
    restored=dict(values);text_edits(restored,edits['cleanup'],api,reverse=True)
    parent=json.loads(restored[PARENT]);binding=parent.pop('producer_cleanup_binding')
    api.need(binding['files']==profile['intermediate']['files']and all(binding['before_bodies'][n].encode()==intermediate[n]for n in edits['cleanup']),'whole cleanup before bodies')
    restored[PARENT]=api.encoded(parent);seal(restored,api);api.need(restored==intermediate,'entire descriptor intermediate inverse')
    text_edits(restored,edits['descriptor'],api,reverse=True)
    package=json.loads(restored['implementation/profile.json']);original=json.loads(before['implementation/profile.json'])
    for case in CASES:
        name='cases/'+case+'/scripts/update/aux_copy.py';restored[name]=api.apply(restored[name],[[contexts['descriptor']['descriptor_before'],contexts['descriptor']['descriptor_after']]],reverse=True)
        cfgname='cases/'+case+'/upgrade-config.json';cfg=json.loads(restored[cfgname]);cfg['code_pins']['scripts/update/aux_copy.py']=api.pin(before[name])['sha256'];restored[cfgname]=api.encoded(cfg)
        row=package['old_source_lineage'][case]['scripts/update/aux_copy.py'];api.need(row['extra']==[dict(before=contexts['descriptor']['descriptor_before'],after=contexts['descriptor']['descriptor_after'])],'only exact descriptor lineage extension')
        row['extra']=[];row['after']=api.pin(before[name]);api.need(row==original['old_source_lineage'][case]['scripts/update/aux_copy.py'],'whole original descriptor lineage')
        for n in('scripts/update/aux_copy.py','upgrade-config.json'):package['cases'][case][n]=original['cases'][case][n]
    restored['implementation/profile.json']=api.encoded(package);parent=json.loads(restored[PARENT]);binding=parent.pop('descriptor_source_binding')
    api.need(binding['files']==profile['parent']['files']and all(binding['before_bodies'][n].encode()==before[n]for n in binding['before_bodies']),'whole descriptor before bodies')
    restored[PARENT]=api.encoded(parent);seal(restored,api);api.need(restored==before,'ENTIRE public360 before inverse; every held body/clock/security operand')
    return restored

def database(before,profile,context,edits,api):
    """Only selected607 exact Apps6/16 DB prefixes; original604 is DATA held."""
    values=dict(before);text_edits(values,edits['database'],api)
    package=json.loads(before['implementation/profile.json'])
    for case in CASES:
        name='scripts/ci/full-root-upgrade/root_upgrade.py';path='cases/'+case+'/'+name
        values[path]=api.apply(before[path],[[context['line_before'],context['line_after']]])
        cfgname='cases/'+case+'/upgrade-config.json';cfg=json.loads(before[cfgname]);api.need(cfg['code_pins'][name]==api.pin(before[path])['sha256'],'original exact capsule helper seal')
        cfg['code_pins'][name]=api.pin(values[path])['sha256'];values[cfgname]=api.encoded(cfg)
        api.need(package['old_source_lineage'][case][name]==context['lineage_before'][case],'entire prior typed helper lineage')
        package['old_source_lineage'][case][name]=copy.deepcopy(profile['database_lineage_after'][case])
        package['cases'][case][name]=api.pin(values[path]);package['cases'][case]['upgrade-config.json']=api.pin(values[cfgname])
    values['implementation/profile.json']=api.encoded(package)
    binding=copy.deepcopy(context);binding['files']=profile['database_parent']['files'];binding['before_bodies']={n:before[n].decode()for n in edits['database']}
    parent=json.loads(before[PARENT]);api.need('database_preservation_binding'not in parent,'fresh selected database context');parent['database_preservation_binding']=binding;values[PARENT]=api.encoded(parent);seal(values,api)
    return values

def database_inverse(values,before,profile,context,edits,api):
    """Restore ALL public027a bytes before the held descriptor/cleanup inverse."""
    restored=dict(values);text_edits(restored,edits['database'],api,reverse=True)
    package=json.loads(restored['implementation/profile.json']);original=json.loads(before['implementation/profile.json'])
    for case in CASES:
        name='scripts/ci/full-root-upgrade/root_upgrade.py';path='cases/'+case+'/'+name
        restored[path]=api.apply(restored[path],[[context['line_before'],context['line_after']]],reverse=True)
        cfgname='cases/'+case+'/upgrade-config.json';cfg=json.loads(restored[cfgname]);api.need(cfg['code_pins'][name]==api.pin(values[path])['sha256'],'current actual helper seal before inverse');cfg['code_pins'][name]=api.pin(before[path])['sha256'];restored[cfgname]=api.encoded(cfg)
        api.need(package['old_source_lineage'][case][name]==profile['database_lineage_after'][case],'exact complete current typed lineage')
        package['old_source_lineage'][case][name]=copy.deepcopy(context['lineage_before'][case])
        for n in(name,'upgrade-config.json'):package['cases'][case][n]=original['cases'][case][n]
    restored['implementation/profile.json']=api.encoded(package);parent=json.loads(restored[PARENT]);binding=parent.pop('database_preservation_binding')
    expected=copy.deepcopy(context);expected['files']=profile['database_parent']['files'];expected['before_bodies']={n:before[n].decode()for n in edits['database']}
    api.need(binding==expected,'whole source-owned database context and before bodies')
    restored[PARENT]=api.encoded(parent);seal(restored,api);api.need(restored==before and {n:api.pin(b)for n,b in restored.items()}==profile['database_parent']['files'],'ENTIRE public027a360 inverse; no other field/runtime/clock change')
    return restored
