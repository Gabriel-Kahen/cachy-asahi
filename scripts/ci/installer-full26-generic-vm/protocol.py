# SPDX-License-Identifier: MIT
"""Injected full26 event validator; original22 call rules remain unchanged."""
def transaction_event(event, nonce, selection, source):
    keys = {'event','nonce','selection_sha256','fixture_source','uid','gid','tests','failures','errors','skips',
            'status','methods','first_failure','class_cleanups_returned','cancelled','duties','scope','barrier_report'}
    require(type(event) is dict and set(event) == keys and event['event'] == 'transaction_result' and
            event['nonce'] == nonce and event['selection_sha256'] == selection and event['fixture_source'] == source and
            type(source) is str and re.fullmatch('[0-9a-f]{40}', source) and
            type(event['uid']) is int and event['uid'] == 23001 and type(event['gid']) is int and event['gid'] == 23001 and
            all(type(event[k]) is int and 0 <= event[k] <= (26 if k == 'tests' else 32) for k in ('tests','failures','errors','skips')) and
            type(event['class_cleanups_returned']) is bool and type(event['cancelled']) is bool,
            'transaction event identity/counts differ')
    require(type(event['methods']) is list and len(event['methods']) <= 17, 'bounded transaction methods required')
    for i,row in enumerate(event['methods']):
        transaction_method(row,i,complete=event['status']=='PASS_GENERIC_ARM_FULL26' or i<len(event['methods'])-1)
    order=[(cls,name) for cls,names in FULL26_SELECTED.items() for name in names]
    require(event['scope']=='GENERIC_ARM_FULL26_ORIGINAL_METHODS_SOFTWARE_ONLY' and
            type(event['duties']) is list and len(event['duties'])<=26 and
            len(event['duties'])<=event['tests']<=len(event['duties'])+1, 'full26 scope/method count differs')
    for i,duty in enumerate(event['duties']):
        require(type(duty) is dict and set(duty)=={'cls','method','status'} and
                (duty['cls'],duty['method'])==order[i] and duty['status'] in ('PASS','FAIL','ERROR','SKIP'),
                'full26 original duty identity/order/status differs')
    if event['status']=='PASS_GENERIC_ARM_FULL26':
        require(len(event['duties'])==26 and all(d['status']=='PASS' for d in event['duties']), 'every original duty must pass')
        expected={'status':'PASS-barrier-only','worker_sha256':TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'],
            'outside_errno':30,'uid':0,'namespace_changed':True,
            'denied_service_syscalls':{str(n):1 for n in (203,206,211,269,425,426,427)},
            'capabilities':{'CapEff':0x400cb,'CapPrm':0x400cb,'CapBnd':0x400cb,'CapInh':0,'CapAmb':0},
            'no_new_privileges':1,'libalpm_initialized':False,'package_commit':False,
            'host_namespace_unchanged':True,'outside_bytes_unchanged':True,'guest_file_absent_on_host':True,'evidence_marker_persisted':True}
        require(json.dumps(event['barrier_report'],sort_keys=True)==json.dumps(expected,sort_keys=True), 'full26 original barrier proof differs')
    failure = event['first_failure']
    if failure is not None:
        # Reuse the existing closed exception/errno/tool domain, with selected Source line bounds.
        proxy = dict(event='barrier_result', nonce=nonce, selection_sha256=selection, fixture_source=BARRIER_SOURCE,
                     uid=23001,gid=23001,tests=0,failures=0,errors=1,skips=0,status='FAIL',report=None,first_failure=failure)
        old_frames = failure.get('frames') if type(failure) is dict else None
        require(type(old_frames) is list and len(old_frames) <= 8 and all(type(row) is dict and set(row)=={'source','line'} and
                row['source'] in TRANSACTION_FRAME_LINES and type(row['line']) is int and
                1 <= row['line'] <= TRANSACTION_FRAME_LINES[row['source']] for row in old_frames), 'transaction failure frames differ')
        proxy['first_failure'] = failure | {'frames': []}
        barrier_event(proxy, nonce, selection)
    if event['status'] == 'PASS_GENERIC_ARM_FULL26':
        require(event['tests'] == 26 and not any(event[k] for k in ('failures','errors','skips')) and
                len(event['methods']) == 17 and sum(len(row['calls']) for row in event['methods']) == 22 and failure is None and event['class_cleanups_returned'] and not event['cancelled'],
                'incomplete transaction fixture proof')
    else:
        require(event['status'] == 'FAIL' and (failure is not None or event['skips'] > 0), 'invalid failed transaction fixture')
    require(len(json.dumps(event)) <= 8192, 'transaction event bound')
    return event
