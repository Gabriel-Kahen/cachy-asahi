# SPDX-License-Identifier: MIT
"""Owned local image aliases; callback-only, with retained actor references."""
import hashlib
import json
from pathlib import Path
import re

LABEL = 'org.cachy-asahi.native-developer'
ROLES = ('base', 'tools')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
DOCKER = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock']
CLOSED = ('natural_exit', 'group_absent', 'exit_observed_via_waitpid', 'leader_held_until_group_inspection')
BUILD_KEYS = ('argv', 'log', 'status', 'exit', *CLOSED, 'ownership_lost', 'forced_cleanup', 'retirement')


class ImageGuard(ValueError):
    def __init__(self, code, ledger=None):
        super().__init__(code); self.code = code; self.ledger = ledger


def _need(ok, code):
    if not ok: raise ImageGuard(code)


def _copy(value):
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


def _own(own):
    _need(type(own) is dict and set(own) == {'source', 'ref', 'run', 'attempt', 'token'}, 'IMAGE_BINDING_REFUSED')
    _need(type(own['source']) is str and re.fullmatch('[0-9a-f]{40}', own['source']) and type(own['ref']) is str
          and own['ref'].startswith('refs/heads/codex/') and type(own['run']) is str and re.fullmatch('[1-9][0-9]*', own['run'])
          and type(own['attempt']) is int and own['attempt'] == 1, 'IMAGE_BINDING_REFUSED')
    _need(own['token'] == hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24], 'IMAGE_BINDING_REFUSED')


def _aliases(own):
    return {r: 'native-developer-' + r + ':' + own['token'] for r in ROLES}


def _closed(row):
    return (type(row) is dict and row.get('status') == 'PASS' and type(row.get('exit')) is int and row['exit'] == 0
            and all(row.get(k) is True for k in CLOSED) and row.get('ownership_lost') is False
            and row.get('forced_cleanup') is False and row.get('retirement') == 'REAPED')


def _call(actor, context, *args):
    _need(type(actor.rows) is list, 'IMAGE_ACTOR_ROWS_REFUSED')
    index = len(actor.rows); check = dict(actor_scope=context['actor_scope'], actor_index=index,
        argv=DOCKER+list(args), log=None, status='REFUSED', code='IMAGE_QUERY_OR_REMOVAL_REFUSED')
    context['query_checks'].append(check)
    try:
        value = actor.docker(*args, timeout=10)
        _need(len(actor.rows) == index+1, 'IMAGE_ACTOR_ROWS_REFUSED')
        row = actor.rows[index]; check['log'] = row.get('log')
        _need(_closed(row) and row.get('argv') == check['argv'] and type(row.get('log')) is str, 'IMAGE_ACTOR_ROW_REFUSED')
        _need(type(value) is str and len(value.encode()) <= 1024**2, 'IMAGE_STDOUT_REFUSED')
        check.update(status='PASS', code='EXACT_RETIRED_ACTOR_STDOUT', stdout_bytes=len(value.encode()), stdout_sha256=hashlib.sha256(value.encode()).hexdigest())
        return value
    except Exception as error:
        if len(actor.rows) == index+1 and type(actor.rows[index]) is dict: check['log'] = actor.rows[index].get('log')
        check['code'] = error.code if isinstance(error, ImageGuard) else 'IMAGE_QUERY_OR_REMOVAL_REFUSED'
        raise ImageGuard(check['code']) from None


def _ids(text):
    _need(len(text.encode()) <= 4096, 'IMAGE_QUERY_REFUSED'); values = text.split()
    _need(len(values) <= 16 and len(values) == len(set(values)) and all(IMAGE.fullmatch(v) for v in values), 'IMAGE_QUERY_REFUSED')
    return sorted(values)


def _query(actor, context, alias):
    return _ids(_call(actor, context, 'image', 'ls', '--no-trunc', '-q', '--filter', 'reference='+alias))


def _owned(actor, context, own):
    return _ids(_call(actor, context, 'image', 'ls', '--no-trunc', '-q', '--filter', 'label='+LABEL+'='+own['token']))


def _build(row, ledger, role):
    _need(_closed(row), 'IMAGE_BUILD_PROOF_REFUSED')
    argv = row.get('argv'); _need(type(argv) is list and len(argv) == 16 and all(type(v) is str for v in argv), 'IMAGE_BUILD_COMMAND_REFUSED')
    own=ledger['binding']; tag=ledger['aliases'][role]
    prefix = (DOCKER+['build','--no-cache','--tag',tag,'--label',LABEL+'='+own['token'],'--label',LABEL+'.source='+own['source'],'--network=none','--pull=false','--platform=linux/arm64'] if role=='base' else
              DOCKER+['build','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--tag',tag,'--label',LABEL+'='+own['token'],'--label',LABEL+'.source='+own['source']])
    _need(argv[:-3] == prefix and argv[-3] == '--iidfile', 'IMAGE_BUILD_COMMAND_REFUSED')
    iid,context=Path(argv[-2]),Path(argv[-1]); directory='bootstrap' if role=='base' else 'overlay'
    _need(iid.is_absolute() and '..' not in iid.parts and str(iid)==argv[-2] and iid.name=='image-id' and iid.parent.name==directory
          and context==iid.parent/'context' and str(context)==argv[-1], 'IMAGE_BUILD_COMMAND_REFUSED')
    _need(type(row.get('log')) is str and len(row['log'])<=4096, 'IMAGE_BUILD_PROOF_REFUSED')
    if role=='base': _need(row['log']==str(iid.parent/'bootstrap.log'), 'IMAGE_BUILD_PROOF_REFUSED')


def _ledger(ledger):
    _need(type(ledger) is dict and ledger.get('schema')==1, 'IMAGE_LEDGER_REFUSED'); _own(ledger['binding'])
    _need(ledger['actor_scope']=='owner' and ledger['aliases']==_aliases(ledger['binding']) and ledger['status']=='PASS_FRESH_LOCAL_ALIAS_BASELINE'
          and ledger['baseline']==dict(aliases={r:[] for r in ROLES},owned_image_ids=[]) and type(ledger['created']) is dict
          and set(ledger['created'])<=set(ROLES) and type(ledger['base_checks']) is list and type(ledger['query_checks']) is list, 'IMAGE_LEDGER_REFUSED')
    for role,row in ledger['created'].items():
        _need(row['alias']==ledger['aliases'][role] and IMAGE.fullmatch(row['image_id']), 'IMAGE_LEDGER_REFUSED'); _build(row['build'],ledger,role)


def _inspect(actor, context, selector, expected, own, allowed):
    rows=json.loads(_call(actor,context,'image','inspect',selector))
    _need(type(rows) is list and len(rows)==1 and type(rows[0]) is dict,'IMAGE_INSPECT_REFUSED')
    row=rows[0]; tags=row.get('RepoTags'); labels=row.get('Config',{}).get('Labels')
    _need(row.get('Id')==expected and row.get('Architecture')=='arm64' and row.get('Os')=='linux' and type(labels) is dict
          and labels.get(LABEL)==own['token'] and labels.get(LABEL+'.source')==own['source'],'IMAGE_IDENTITY_REFUSED')
    _need(type(tags) is list and all(type(t) is str for t in tags) and len(tags)==len(set(tags)) and set(tags)<=allowed,'IMAGE_FOREIGN_ALIAS_REFUSED')
    return dict(image_id=expected,repo_tags=sorted(tags),token=own['token'],source=own['source'])


def _verify(actor, context, ledger, role, expected, allowed):
    alias=ledger['aliases'][role]; start=len(context['query_checks'])
    _need(_query(actor,context,alias)==[expected],'IMAGE_ALIAS_BINDING_REFUSED')
    by_tag=_inspect(actor,context,alias,expected,ledger['binding'],allowed)
    by_id=_inspect(actor,context,expected,expected,ledger['binding'],allowed)
    _need(by_tag==by_id and alias in by_id['repo_tags'],'IMAGE_ALIAS_BINDING_REFUSED')
    return dict(alias=alias,query_indexes=list(range(start,len(context['query_checks']))),**by_id)


def reserve(actor, own):
    """Exact tag and owned-label list queries must exit zero and prove empty."""
    _own(own); ledger=dict(schema=1,binding=_copy(own),aliases=_aliases(own),status='UNKNOWN_LOCAL_ALIAS_BASELINE',
        actor_scope='owner',baseline=dict(aliases={},owned_image_ids=None),baseline_query_indexes=[],created={},base_checks=[],query_checks=[])
    try:
        for role,alias in ledger['aliases'].items(): ledger['baseline']['aliases'][role]=_query(actor,ledger,alias)
        ledger['baseline']['owned_image_ids']=_owned(actor,ledger,own)
        ledger['baseline_query_indexes']=list(range(len(ledger['query_checks'])))
        _need(ledger['baseline']==dict(aliases={r:[] for r in ROLES},owned_image_ids=[]),'IMAGE_PREEXISTING_STATE_REFUSED')
        ledger['status']='PASS_FRESH_LOCAL_ALIAS_BASELINE'; return ledger
    except Exception as error:
        raise ImageGuard(error.code if isinstance(error,ImageGuard) else 'IMAGE_BASELINE_QUERY_REFUSED',ledger) from None


def register(actor, ledger, role, imageid, build_row):
    """Only a successful known source build can grant alias retirement authority."""
    try:
        _ledger(ledger); _need(role in ROLES and role not in ledger['created'] and type(imageid) is str and IMAGE.fullmatch(imageid),'IMAGE_REGISTRATION_REFUSED')
        _build(build_row,ledger,role)
        indexes=[i for i,row in enumerate(actor.rows) if row is build_row]
        _need(len(indexes)==1,'IMAGE_BUILD_ACTOR_REFUSED')
        allowed={r['alias'] for r in ledger['created'].values()}|{ledger['aliases'][role]}
        proof=_verify(actor,ledger,ledger,role,imageid,allowed)
        ledger['created'][role]=dict(alias=ledger['aliases'][role],image_id=imageid,build_actor_index=indexes[0],
            build=_copy({k:build_row[k] for k in BUILD_KEYS}),registration=proof)
        return proof
    except Exception as error:
        raise ImageGuard(error.code if isinstance(error,ImageGuard) else 'IMAGE_REGISTRATION_QUERY_REFUSED',ledger) from None


def verify_base(actor, ledger, phase=None):
    """Verify local FROM tag before and after overlay, even after build failure."""
    _ledger(ledger); _need('base' in ledger['created'],'IMAGE_BASE_UNREGISTERED')
    expected='before_overlay' if not ledger['base_checks'] else 'after_overlay'; phase=expected if phase is None else phase
    _need(len(ledger['base_checks'])<2 and phase==expected,'IMAGE_BASE_PHASE_REFUSED')
    row=dict(phase=phase,status='REFUSED',query_indexes=[]); start=len(ledger['query_checks'])
    try:
        row.update(_verify(actor,ledger,ledger,'base',ledger['created']['base']['image_id'],{r['alias'] for r in ledger['created'].values()}),status='PASS')
    except Exception as error:
        row.update(code=error.code if isinstance(error,ImageGuard) else 'IMAGE_BASE_QUERY_REFUSED',query_indexes=list(range(start,len(ledger['query_checks']))))
        ledger['base_checks'].append(row); raise ImageGuard(row['code'],ledger) from None
    ledger['base_checks'].append(row); return ledger['aliases']['base']


def retire(actor, ledger):
    """Prove all candidates first; remove only aliases, with independent final queries."""
    result=dict(schema=1,status='UNKNOWN_IMAGE_ALIAS_RETIREMENT',binding=None,actor_scope='retirement',ledger=None,
        preflight=dict(aliases={},owned_image_ids=None),preflight_query_indexes=[],removed_aliases=[],removals=[],
        final=dict(aliases={r:None for r in ROLES},owned_image_ids=None),final_query_indexes={},query_checks=[],codes=[])
    valid=False
    try:
        _ledger(ledger); valid=True; result['binding']=_copy(ledger['binding']); result['ledger']=_copy(ledger)
        aliases=ledger['aliases']; own=ledger['binding']; created=ledger['created']
        allowed={r['alias'] for r in created.values()}; known={r['image_id'] for r in created.values()}
        for role,alias in aliases.items(): result['preflight']['aliases'][role]=_query(actor,result,alias)
        result['preflight']['owned_image_ids']=_owned(actor,result,own)
        result['preflight_query_indexes']=list(range(len(result['query_checks'])))
        _need(set(result['preflight']['owned_image_ids'])<=known,'IMAGE_UNREGISTERED_ID_HELD')
        candidates=[]
        for role in reversed(ROLES):
            ids=result['preflight']['aliases'][role]
            if not ids: continue
            _need(role in created and ids==[created[role]['image_id']],'IMAGE_UNREGISTERED_OR_REBOUND_ALIAS_HELD')
            _verify(actor,result,ledger,role,created[role]['image_id'],allowed); candidates.append(role)
        for role in candidates:
            proof=_verify(actor,result,ledger,role,created[role]['image_id'],allowed)
            index=len(result['query_checks']); _call(actor,result,'image','rm',aliases[role])
            result['removed_aliases'].append(aliases[role]); result['removals'].append(dict(proof,removal_query_index=index))
    except Exception as error:
        result['codes'].append(error.code if isinstance(error,ImageGuard) else 'IMAGE_QUERY_OR_REMOVAL_REFUSED')
    if valid:
        for role in ROLES:
            result['final_query_indexes'][role]=len(result['query_checks'])
            try: result['final']['aliases'][role]=_query(actor,result,ledger['aliases'][role])
            except Exception: result['codes'].append('IMAGE_FINAL_ALIAS_QUERY_REFUSED')
        result['final_query_indexes']['owned_image_ids']=len(result['query_checks'])
        try: result['final']['owned_image_ids']=_owned(actor,result,ledger['binding'])
        except Exception: result['codes'].append('IMAGE_FINAL_OWNED_QUERY_REFUSED')
        if any(v!=[] for v in result['final']['aliases'].values()) or result['final']['owned_image_ids']!=[]:
            result['codes'].append('IMAGE_FINAL_STATE_NOT_EMPTY')
        if not result['codes']: result['status']='PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED'
    return result
