"""New exception DATA controls; no HTTP, DNS lookup, Source actor or reader."""
import argparse
import ast
import copy
import errno
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
import time
import unittest
import urllib.error

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--parent-source',type=Path,required=True)
ARGS,TEST_ARGS=parser.parse_known_args()
spec=importlib.util.spec_from_file_location('typed_transport',HERE/'payload/native/bootstrap_inputs.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class AcquisitionError(ValueError):
    def __init__(self,name='rootfs',category='HTTPS transport failure',code=None):
        self.filename,self.category,self.http_status=name,category,code

# Actually raise/catch the same two categories as the unchanged trusted parent,
# then suppress display chaining. __context__ must remain genuinely attached.
def parent_error(cause,name='rootfs'):
    try:
        raise cause
    except (urllib.error.URLError,TimeoutError):
        try:
            raise AcquisitionError(name) from None
        except AcquisitionError as error:
            return error

class Controls(unittest.TestCase):
    def classify(self,reason):
        error=parent_error(urllib.error.URLError(reason))
        self.assertIs(type(error.__context__),urllib.error.URLError)
        self.assertIs(error.__context__.reason,reason)
        self.assertTrue(error.__suppress_context__)
        self.assertIsNone(error.__cause__)
        return M._transport_cause(error,AcquisitionError)

    def test_real_suppressed_dns_context_retains_only_type_proof(self):
        p=self.classify(socket.gaierror(-2,'PRIVATE-DNS-ADDRESS.example'))
        self.assertEqual(p,dict(family='DNS',basis='EXACT_STDLIB_EXCEPTION_TYPE',path=['context','reason'],context_suppressed=True,received_bytes=None))
        self.assertNotIn('PRIVATE',json.dumps(p))

    def test_direct_timeout_context_is_supported(self):
        error=parent_error(TimeoutError('PRIVATE-timeout-value'))
        p=M._transport_cause(error,AcquisitionError)
        self.assertEqual((p['family'],p['path']),('TIMEOUT',['context']))
        self.assertIsNone(p['received_bytes'])

    def test_closed_tls_certificate_and_tls_types(self):
        for error,family in [(ssl.SSLCertVerificationError(1,'PRIVATE-cert'), 'TLS_CERTIFICATE'),(ssl.SSLError(1,'PRIVATE-tls'),'TLS'),(ssl.SSLEOFError(1,'PRIVATE-eof'),'TLS'),(ssl.SSLZeroReturnError(1,'PRIVATE-close'),'TLS'),(ssl.SSLWantReadError(1,'PRIVATE-read'),'TLS'),(ssl.SSLWantWriteError(1,'PRIVATE-write'),'TLS')]:
            with self.subTest(kind=type(error).__name__):self.assertEqual(self.classify(error)['family'],family)

    def test_closed_connection_errno_and_name_resolution_types(self):
        for error,family in [(ConnectionError('PRIVATE'),'CONNECTION'),(ConnectionAbortedError('PRIVATE'),'CONNECTION'),(ConnectionRefusedError('PRIVATE'),'CONNECTION'),(ConnectionResetError('PRIVATE'),'CONNECTION'),(BrokenPipeError('PRIVATE'),'CONNECTION'),(OSError(errno.EHOSTUNREACH,'PRIVATE'),'CONNECTION'),(OSError(errno.ENETUNREACH,'PRIVATE'),'CONNECTION'),(OSError(errno.ETIMEDOUT,'PRIVATE'),'TIMEOUT'),(socket.herror(1,'PRIVATE'),'DNS'),(OSError(errno.EINVAL,'PRIVATE'),'UNKNOWN')]:
            with self.subTest(kind=type(error).__name__):self.assertEqual(self.classify(error)['family'],family)

    def test_messages_and_unrelated_context_are_not_cause_evidence(self):
        for reason in ('timed out https://USER:PASSWORD@address/','certificate verify failed',None,123,{'errno':errno.ECONNREFUSED}):
            p=self.classify(reason);self.assertEqual(p['family'],'UNKNOWN');self.assertNotIn('PASSWORD',json.dumps(p))
        # A known older context does not override an opaque URLError.reason.
        error=parent_error(urllib.error.URLError('opaque'))
        error.__context__.__context__=socket.gaierror(-2,'PRIVATE')
        self.assertEqual(M._transport_cause(error,AcquisitionError)['family'],'UNKNOWN')

    def test_only_the_parent_context_grammar_is_supported(self):
        for context in (socket.gaierror(-2,'PRIVATE'),ssl.SSLError('PRIVATE'),ConnectionError('PRIVATE'),ValueError('PRIVATE')):
            error=AcquisitionError();error.__context__=context
            self.assertEqual(M._transport_cause(error,AcquisitionError)['family'],'UNKNOWN')
        error=AcquisitionError();error.__cause__=TimeoutError('PRIVATE')
        self.assertEqual(M._transport_cause(error,AcquisitionError)['family'],'UNKNOWN')

    def test_subclasses_and_hostile_metaclass_never_run_user_hooks(self):
        events=[]
        class Meta(type):
            def __eq__(self,other):events.append('type-eq');raise AssertionError('user hook')
        class Evil(Exception,metaclass=Meta):
            def __getattribute__(self,name):events.append(name);raise AssertionError('user hook')
            def __str__(self):events.append('str');raise AssertionError('user hook')
        class SubTLS(ssl.SSLError):pass
        class SubURL(urllib.error.URLError):pass
        for reason in (Evil(),SubTLS('PRIVATE')):
            self.assertEqual(self.classify(reason)['family'],'UNKNOWN')
        error=AcquisitionError();error.__context__=SubURL(TimeoutError())
        self.assertEqual(M._transport_cause(error,AcquisitionError)['family'],'UNKNOWN')
        self.assertEqual(events,[])

    def test_descriptor_access_bypasses_custom_exception_properties(self):
        events=[]
        class Trusted(ValueError):
            def __getattribute__(self,name):events.append(name);raise AssertionError('attribute hook')
        try:
            raise TimeoutError('PRIVATE')
        except TimeoutError:
            try:raise Trusted() from None
            except Trusted as error:p=M._transport_cause(error,Trusted)
        self.assertEqual(p['family'],'TIMEOUT');self.assertEqual(events,[])

    def test_reason_storage_refuses_hostile_keys_and_oversized_shapes(self):
        events=[]
        class Key:
            def __hash__(self):return hash('reason')
            def __eq__(self,other):events.append('key-eq');raise AssertionError('key hook')
        url=urllib.error.URLError(TimeoutError());url.__dict__={Key():TimeoutError()}
        self.assertEqual(M._transport_cause(parent_error(url),AcquisitionError)['family'],'UNKNOWN')
        url=urllib.error.URLError(TimeoutError());url.__dict__.update({str(i):None for i in range(8)})
        self.assertEqual(M._transport_cause(parent_error(url),AcquisitionError)['family'],'UNKNOWN')
        self.assertEqual(events,[])

    def test_cycles_and_nested_reason_depth_are_bounded(self):
        a=urllib.error.URLError(None);b=urllib.error.URLError(a);a.reason=b
        p=M._transport_cause(parent_error(a),AcquisitionError)
        self.assertEqual(p['family'],'UNKNOWN');self.assertIn('CYCLIC',p['basis']);self.assertLessEqual(len(p['path']),5)
        reason=TimeoutError()
        for _ in range(4):reason=urllib.error.URLError(reason)
        self.assertEqual(M._transport_cause(parent_error(reason),AcquisitionError)['family'],'TIMEOUT')
        reason=urllib.error.URLError(reason)
        p=M._transport_cause(parent_error(reason),AcquisitionError)
        self.assertEqual(p['family'],'UNKNOWN');self.assertLessEqual(len(json.dumps(p)),512)

    def test_opaque_reason_never_formats_strings_or_reprs(self):
        events=[]
        class Secret:
            def __str__(self):events.append('str');raise AssertionError('formatting')
            def __repr__(self):events.append('repr');raise AssertionError('formatting')
        p=self.classify(Secret());self.assertEqual(p['family'],'UNKNOWN');json.dumps(p);self.assertEqual(events,[])

    def test_function_does_not_open_process_or_network_during_data_parse(self):
        events=[]
        def audit(event,args):
            if event=='open' or event.startswith(('socket.','subprocess.','os.exec','os.fork','os.spawn','os.posix_spawn','ctypes.')):
                events.append(event);raise AssertionError('DATA side effect')
        # Keep this audit interval local without a permanent test-process hook.
        # subprocess/socket/open are not used by this helper's entire AST.
        fn=next(n for n in ast.parse((HERE/'payload/native/bootstrap_inputs.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='_transport_cause')
        calls=[n for n in ast.walk(fn)if isinstance(n,ast.Call)]
        self.assertFalse(any(isinstance(n.func,ast.Name)and n.func.id in ('open','exec','eval','compile','__import__')for n in calls))
        # An actual event guard can be enabled after all file reads are complete.
        error=parent_error(urllib.error.URLError(TimeoutError()))
        active=[True]
        def guarded(event,args):
            if active[0]:audit(event,args)
        sys.addaudithook(guarded)
        try:self.assertEqual(M._transport_cause(error,AcquisitionError)['family'],'TIMEOUT')
        finally:active[0]=False
        self.assertEqual(events,[])

    def bound(self,effects):
        original=json.loads((ARGS.parent_source/'bootstrap/scripts/ci/inputs.lock.json').read_bytes())
        extras=json.loads((ARGS.parent_source/'native/input-profile.json').read_bytes())['additions']['rows']
        calls=[];diagnostics={};row=original['rootfs'];cache=Path('/tmp/typed-cause-data-cache')
        def fetch(item,path):
            calls.append((copy.deepcopy(item),path));effect=effects[len(calls)-1]
            if isinstance(effect,BaseException):raise effect
            return effect
        result=M.bind_fetch(original,extras,cache,lambda *args:None,fetch,AcquisitionError,diagnostics,time.monotonic()+30)
        return result,row,cache,calls,diagnostics

    def test_new_attempt_facts_preserve_first_typed_failure_after_success(self):
        # Attach the real from-None context before handing it through the saved
        # parent's callback, as the native fetch itself does.
        error=parent_error(urllib.error.URLError(socket.gaierror(-2,'PRIVATE')),
                           'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz')
        fetch,row,cache,calls,d=self.bound([error,'PASS'])
        self.assertEqual(fetch(row,cache),'PASS');self.assertEqual(len(calls),2)
        self.assertEqual(calls[0],calls[1]);self.assertEqual([r['status']for r in d['attempts']],['FAIL','PASS'])
        self.assertEqual(d['attempts'][0]['transport_cause']['family'],'DNS')
        self.assertIsNone(d['attempts'][1]['transport_cause'])
        self.assertTrue(all(r['received_bytes']is None for r in d['attempts']))
        self.assertEqual(d['original_cause'],'UNKNOWN_DNS_TLS_TIMEOUT_OR_OTHER_TRANSPORT')

    def test_unknown_cause_keeps_retry_policy_and_http_still_never_retries(self):
        error=parent_error(urllib.error.URLError('opaque'),'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz')
        fetch,row,cache,calls,d=self.bound([error,'PASS']);self.assertEqual(fetch(row,cache),'PASS');self.assertEqual(len(calls),2)
        self.assertEqual(d['attempts'][0]['transport_cause']['family'],'UNKNOWN')
        error=AcquisitionError(row['filename'],'HTTP failure',503)
        fetch,row,cache,calls,d=self.bound([error])
        with self.assertRaises(AcquisitionError):fetch(row,cache)
        self.assertEqual(len(calls),1);self.assertIsNone(d['attempts'][0]['transport_cause'])

    def test_complete_existing_bind_function_inverse_holds(self):
        before=(ARGS.parent_source/'native/bootstrap_inputs.py').read_text();after=(HERE/'payload/native/bootstrap_inputs.py').read_text()
        funcs=lambda raw:{n.name:ast.get_source_segment(raw,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
        old,new=funcs(before),funcs(after)
        s=new['bind_fetch'].replace(",\n                          transport_cause=None)",")").replace("                if exact and error.category == 'HTTPS transport failure' and error.http_status is None:\n                    record['transport_cause'] = _transport_cause(error, acquisition_error)\n",'')
        self.assertEqual(s,old['bind_fetch'])
        self.assertTrue(all(new[name]==body for name,body in old.items()if name!='bind_fetch'))

if __name__=='__main__':unittest.main(argv=['test_typed_cause.py',*TEST_ARGS],verbosity=2)
